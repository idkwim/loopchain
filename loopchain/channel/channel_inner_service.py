# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import ast
import json
import pickle
import re
import signal
import multiprocessing as mp
from asyncio import Condition
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from earlgrey import *

from loopchain import configure as conf
from loopchain import utils as util
from loopchain.baseservice import BroadcastCommand, BroadcastScheduler, ScoreResponse
from loopchain.blockchain import (Transaction, TransactionSerializer, TransactionVerifier, TransactionVersioner,
                                  Block, BlockBuilder, BlockSerializer, blocks, Hash32, )
from loopchain.blockchain.exception import *
from loopchain.channel.channel_property import ChannelProperty
from loopchain.consensus import Epoch, VoteMessage
from loopchain.peer.consensus_siever import ConsensusSiever
from loopchain.protos import loopchain_pb2, message_code
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.channel.channel_service import ChannelService



class ChannelTxCreatorInnerTask:
    def __init__(self, channel_name: str, peer_target: str, tx_versioner: TransactionVersioner):
        self.__channel_name = channel_name
        self.__tx_versioner = tx_versioner

        scheduler = BroadcastScheduler(channel=channel_name, self_target=peer_target)
        scheduler.start()

        self.__broadcast_scheduler = scheduler

        future = scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_target)
        future.result(conf.TIMEOUT_FOR_FUTURE)

    def __pre_validate(self, tx: Transaction):
        if conf.CHANNEL_OPTION[self.__channel_name]['send_tx_type'] != conf.SendTxType.icx:
            return

        if not util.is_in_time_boundary(tx.timestamp, conf.ALLOW_TIMESTAMP_BOUNDARY_SECOND):
            raise TransactionInvalidOutOfTimeBound(tx.hash.hex(), tx.timestamp, util.get_now_time_stamp())

    def cleanup(self):
        self.__broadcast_scheduler.stop()
        self.__broadcast_scheduler.wait()
        self.__broadcast_scheduler = None

    @message_queue_task
    async def create_icx_tx(self, kwargs: dict):
        result_code = None
        exception = None
        tx = None

        try:
            tx_version = self.__tx_versioner.get_version(kwargs)

            ts = TransactionSerializer.new(tx_version, self.__tx_versioner)
            tx = ts.from_(kwargs)

            tv = TransactionVerifier.new(tx_version, self.__tx_versioner)
            tv.verify(tx)

            self.__pre_validate(tx)

            logging.debug(f"create icx input : {kwargs}")

            self.__broadcast_scheduler.schedule_job(BroadcastCommand.CREATE_TX, (tx, self.__tx_versioner))
            return message_code.Response.success, tx.hash.hex()

        except TransactionInvalidError as e:
            result_code = e.message_code
            exception = e
            traceback.print_exc()
        except BaseException as e:
            result_code = TransactionInvalidError.message_code
            exception = e
            traceback.print_exc()
        finally:
            if exception:
                logging.warning(f"create_icx_tx: tx restore fail.\n\n"
                                f"kwargs({kwargs})\n\n"
                                f"tx({tx})\n\n"
                                f"exception({exception})")
                return result_code, None

    async def schedule_job(self, command, params):
        self.__broadcast_scheduler.schedule_job(command, params)


class ChannelTxCreatorInnerService(MessageQueueService[ChannelTxCreatorInnerTask]):
    TaskType = ChannelTxCreatorInnerTask

    def __init__(self, broadcast_queue: mp.Queue, amqp_target, route_key, username=None, password=None, **task_kwargs):
        super().__init__(amqp_target, route_key, username, password, **task_kwargs)

        async def _stop_loop():
            self.loop.stop()

        def _schedule_job():
            while True:
                command, params = broadcast_queue.get()
                if command is None:
                    break
                asyncio.run_coroutine_threadsafe(self._task.schedule_job(command, params), self.loop)

            while not broadcast_queue.empty():
                broadcast_queue.get()

            asyncio.run_coroutine_threadsafe(_stop_loop(), self.loop)

        self.__broadcast_thread = threading.Thread(target=_schedule_job)
        self.__broadcast_thread.start()

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")

    def cleanup(self):
        self.__broadcast_thread.join()
        self._task.cleanup()

    @staticmethod
    def main(configurations: dict, channel_name: str, amqp_target: str, amqp_key: str, peer_target: str,
             tx_versioner: TransactionVersioner, broadcast_queue: mp.Queue, start_event: mp.Event=None):
        if start_event is not None:
            start_event.set()

        conf.set_origin_type_configurations(configurations)

        def _on_sigterm():
            logging.error("Channel TX Creator has been received SIGTERM")
            broadcast_queue.put((None, None))

        queue_name = conf.CHANNEL_TX_CREATOR_QUEUE_NAME_FORMAT.format(channel_name=channel_name, amqp_key=amqp_key)
        service = ChannelTxCreatorInnerService(broadcast_queue,
                                               amqp_target,
                                               queue_name,
                                               conf.AMQP_USERNAME,
                                               conf.AMQP_PASSWORD,
                                               channel_name=channel_name,
                                               peer_target=peer_target,
                                               tx_versioner=tx_versioner)

        service.loop.add_signal_handler(signal.SIGTERM, _on_sigterm)

        service.serve(connection_attempts=conf.AMQP_CONNECTION_ATTEMPS,
                      retry_delay=conf.AMQP_RETRY_DELAY, exclusive=True)
        logging.info("ChannelTxCreatorInnerService: started")
        service.serve_all()

        service.cleanup()
        service.loop.close()
        logging.info("ChannelTxCreatorInnerService: stopped")


class ChannelTxCreatorInnerStub(MessageQueueStub[ChannelTxCreatorInnerTask]):
    TaskType = ChannelTxCreatorInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")


class ChannelTxReceiverInnerTask:
    def __init__(self, tx_versioner: TransactionVersioner, tx_queue: mp.Queue):
        self.__tx_versioner = tx_versioner
        self.__tx_queue = tx_queue

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_tx_list(self, request) -> tuple:
        tx_list = []
        for tx_item in request.tx_list:
            tx_json = json.loads(tx_item.tx_json)

            tx_version = self.__tx_versioner.get_version(tx_json)

            ts = TransactionSerializer.new(tx_version, self.__tx_versioner)
            tx = ts.from_(tx_json)

            tv = TransactionVerifier.new(tx_version, self.__tx_versioner)
            tv.verify(tx)

            tx.size(self.__tx_versioner)

            tx_list.append(tx)

        tx_len = len(tx_list)
        if tx_len == 0:
            response_code = message_code.Response.fail
            message = "fail tx validate while AddTxList"
        else:
            self.__tx_queue.put(tx_list)
            response_code = message_code.Response.success
            message = f"success ({len(tx_list)})/({len(request.tx_list)})"

        return response_code, message


class ChannelTxReceiverInnerService(MessageQueueService[ChannelTxReceiverInnerTask]):
    TaskType = ChannelTxReceiverInnerTask

    def __init__(self, amqp_target, route_key, username=None, password=None, **task_kwargs):
        super().__init__(amqp_target, route_key, username, password, **task_kwargs)

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")

    @staticmethod
    def main(configurations: dict, channel_name: str, amqp_target: str, amqp_key: str,
             tx_versioner: TransactionVersioner, tx_queue: mp.Queue, start_event: mp.Event=None):
        if start_event is not None:
            start_event.set()

        conf.set_origin_type_configurations(configurations)

        queue_name = conf.CHANNEL_TX_RECEIVER_QUEUE_NAME_FORMAT.format(channel_name=channel_name, amqp_key=amqp_key)
        service = ChannelTxReceiverInnerService(amqp_target, queue_name,
                                                conf.AMQP_USERNAME, conf.AMQP_PASSWORD,
                                                tx_versioner=tx_versioner, tx_queue=tx_queue)

        async def _stop_loop():
            service.loop.stop()

        def _on_sigterm():
            logging.error("Channel TX Receiver has been received SIGTERM")
            asyncio.run_coroutine_threadsafe(_stop_loop(), service.loop)

        service.loop.add_signal_handler(signal.SIGTERM, _on_sigterm)

        service.serve(connection_attempts=conf.AMQP_CONNECTION_ATTEMPS,
                      retry_delay=conf.AMQP_RETRY_DELAY, exclusive=True)
        logging.info("ChannelTxReceiverInnerService: started")
        service.serve_all()

        service.loop.close()

        logging.info("ChannelTxReceiverInnerService: stopped")


class ChannelTxReceiverInnerStub(MessageQueueStub[ChannelTxReceiverInnerTask]):
    TaskType = ChannelTxReceiverInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")


class _ChannelSubProcess:
    def __init__(self):
        self.__context: mp.context.SpawnContext = mp.get_context('spawn')

        self.__process: mp.Process = None
        self.__terminated_lock = threading.Lock()
        self.__join_thread: threading.Thread = None

    def Queue(self, maxsize=0) -> mp.Queue:
        return self.__context.Queue(maxsize=maxsize)

    def start(self, target, args=(), terminated_callback=None, terminated_callback_loop=None):
        if self.__process is not None:
            raise RuntimeError("Process has already been started")
        if terminated_callback is not None and terminated_callback_loop is None:
            raise RuntimeError("If you set terminated_callback, You must set terminated_callback_loop")

        start_event = self.__context.Event()
        self.__process: mp.Process = self.__context.Process(target=target,
                                                            args=args,
                                                            kwargs={'start_event': start_event})
        self.__process.start()
        start_event.wait()

        async def _perform_terminated_callback():
            terminated_callback(self)

        def _join_process(process: mp.Process):
            process.join()
            if terminated_callback is not None:
                with self.__terminated_lock:
                    if self.__process is not None:
                        logging.error(f"Process({self}) crash occurred")
                        self.__process = None
                        asyncio.run_coroutine_threadsafe(_perform_terminated_callback(), terminated_callback_loop)

        self.__join_thread: threading.Thread = threading.Thread(target=_join_process, args=(self.__process,))
        self.__join_thread.start()

    def terminate(self):
        with self.__terminated_lock:
            if self.__process is not None:
                logging.info(f"Terminate process={self}")
                self.__process.terminate()
                self.__process = None

    def join(self):
        if self.__join_thread is None:
            raise RuntimeError("Process has not been started yet")
        self.__join_thread.join()
        self.__join_thread = None


class _ChannelTxCreatorProcess(_ChannelSubProcess):
    def __init__(self, tx_versioner: TransactionVersioner, broadcast_scheduler: BroadcastScheduler,
                 terminated_callback, loop):
        super().__init__()

        self.__broadcast_queue = self.Queue()

        args = (conf.get_origin_type_configurations(),
                ChannelProperty().name,
                StubCollection().amqp_target,
                StubCollection().amqp_key,
                ChannelProperty().peer_target,
                tx_versioner,
                self.__broadcast_queue)
        super().start(target=ChannelTxCreatorInnerService.main, args=args,
                      terminated_callback=terminated_callback, terminated_callback_loop=loop)

        self.__broadcast_scheduler = broadcast_scheduler
        commands = (BroadcastCommand.SUBSCRIBE, BroadcastCommand.UNSUBSCRIBE, BroadcastCommand.UPDATE_AUDIENCE)
        broadcast_scheduler.add_schedule_listener(self.__broadcast_callback, commands=commands)

    def start(self, target, args=(), terminated_callback=None, terminated_callback_loop=None):
        raise AttributeError("Doesn't support this function")

    def join(self):
        self.__broadcast_scheduler.remove_schedule_listener(self.__broadcast_callback)
        super().join()
        self.__broadcast_queue = None

    def __broadcast_callback(self, command, params):
        self.__broadcast_queue.put((command, params))


class _ChannelTxReceiverProcess(_ChannelSubProcess):
    def __init__(self, tx_versioner: TransactionVersioner, add_tx_list_callback, terminated_callback, loop):
        super().__init__()

        self.__tx_queue = self.Queue()

        async def _add_tx_list(tx_list):
            add_tx_list_callback(tx_list)

        def _receive_tx_list(tx_queue):
            while True:
                tx_list = tx_queue.get()
                if tx_list is None:
                    break
                asyncio.run_coroutine_threadsafe(_add_tx_list(tx_list), loop)

            while not tx_queue.empty():
                tx_queue.get()

        self.__receive_thread = threading.Thread(target=_receive_tx_list, args=(self.__tx_queue,))
        self.__receive_thread.start()

        args = (conf.get_origin_type_configurations(),
                ChannelProperty().name,
                StubCollection().amqp_target,
                StubCollection().amqp_key,
                tx_versioner,
                self.__tx_queue)
        super().start(target=ChannelTxReceiverInnerService.main, args=args,
                      terminated_callback=terminated_callback, terminated_callback_loop=loop)

    def start(self, target, args=(), terminated_callback=None, terminated_callback_loop=None):
        raise AttributeError("Doesn't support this function")

    def join(self):
        super().join()
        self.__tx_queue.put(None)
        self.__receive_thread.join()
        self.__tx_queue = None
        self.__receive_thread = None


class ChannelInnerTask:
    def __init__(self, channel_service: 'ChannelService'):
        self._channel_service = channel_service
        self._thread_pool = ThreadPoolExecutor(1, "ChannelInnerThread")

        # Citizen
        self._citizen_condition_new_block: Condition = None
        self._citizen_set = set()

        self.__sub_processes = []
        self.__loop_for_sub_services = None

    def init_sub_service(self, loop):
        if len(self.__sub_processes) > 0:
            raise RuntimeError("Channel sub services have already been initialized")

        if loop is None:
            raise RuntimeError("Channel sub services need a loop")
        self.__loop_for_sub_services = loop

        tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner

        broadcast_scheduler = self._channel_service.broadcast_scheduler
        tx_creator_process = _ChannelTxCreatorProcess(tx_versioner,
                                                      broadcast_scheduler,
                                                      self.__handle_terminated_sub_services,
                                                      loop)
        self.__sub_processes.append(tx_creator_process)
        logging.info(f"Channel({ChannelProperty().name}) TX Creator: initialized")

        tx_receiver_process = _ChannelTxReceiverProcess(tx_versioner,
                                                        self.__add_tx_list,
                                                        self.__handle_terminated_sub_services,
                                                        loop)
        self.__sub_processes.append(tx_receiver_process)
        logging.info(f"Channel({ChannelProperty().name}) TX Receiver: initialized")

    def cleanup_sub_services(self):
        for process in self.__sub_processes:
            process.terminate()
            process.join()
        self.__sub_processes = []

    def __handle_terminated_sub_services(self, process: _ChannelSubProcess):
        try:
            self.__sub_processes.remove(process)
            process.join()

            logging.critical(f"Channel sub process crash occurred. process={process}")

            async def _close():
                self._channel_service.close()

            asyncio.ensure_future(_close(), loop=self.__loop_for_sub_services)
        except ValueError:
            # Call this function by cleanup
            pass

    def __add_tx_list(self, tx_list):
        for tx in tx_list:
            # util.logger.spam(f"channel_inner_service:add_tx tx({tx.get_data_string()})")

            object_has_queue = self._channel_service.get_object_has_queue_by_consensus()
            object_has_queue.add_tx_obj(tx)
            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'AddTx',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {'tx_hash': tx.hash.hex()}})

    @message_queue_task
    async def hello(self):
        return 'channel_hello'

    @message_queue_task
    async def announce_new_block(self, subscriber_block_height: int):
        blockchain = self._channel_service.block_manager.get_blockchain()

        while True:
            my_block_height = blockchain.block_height
            if subscriber_block_height > my_block_height:
                message = {'error': "Announced block height is lower than subscriber's."}
                return json.dumps(message)

            if subscriber_block_height == my_block_height:
                async with self._citizen_condition_new_block:
                    await self._citizen_condition_new_block.wait()

            new_block_height = subscriber_block_height + 1
            new_block = blockchain.find_block_by_height(new_block_height)

            if new_block is None:
                logging.warning(f"Cannot find block height({new_block_height})")
                await asyncio.sleep(0.5)  # To prevent excessive occupancy of the CPU in an infinite loop
                continue

            logging.debug(f"announce_new_block: height({new_block.header.height}), hash({new_block.header.hash}), "
                          f"target: {self._citizen_set}")
            bs = BlockSerializer.new(new_block.header.version, blockchain.tx_versioner)
            return json.dumps(bs.serialize(new_block))

    @message_queue_task
    async def register_subscriber(self, peer_id):
        if len(self._citizen_set) >= conf.SUBSCRIBE_LIMIT:
            return False
        else:
            self._citizen_set.add(peer_id)
            logging.info(f"register new subscriber: {peer_id}")
            logging.debug(f"remaining all subscribers: {self._citizen_set}")
            return True

    @message_queue_task
    async def unregister_subscriber(self, peer_id):
        logging.info(f"unregister subscriber: {peer_id}")
        self._citizen_set.remove(peer_id)
        logging.debug(f"remaining all subscribers: {self._citizen_set}")

    @message_queue_task
    async def is_registered_subscriber(self, peer_id):
        return peer_id in self._citizen_set

    @message_queue_task
    def get_peer_list(self):
        peer_manager = self._channel_service.peer_manager
        return str(peer_manager.peer_list[conf.ALL_GROUP_ID]), str(peer_manager.peer_list)

    @message_queue_task(type_=MessageQueueType.Worker)
    async def reset_leader(self, new_leader, block_height=0) -> None:
        await self._channel_service.reset_leader(new_leader, block_height)

    @message_queue_task(priority=255)
    async def get_status(self):
        block_height = 0
        total_tx = 0

        status_data = dict()

        block_manager = self._channel_service.block_manager
        status_data["made_block_count"] = block_manager.made_block_count
        if block_manager.get_blockchain().last_block is not None:
            block_height = block_manager.get_blockchain().last_block.header.height
            logging.debug("getstatus block hash(block_manager.get_blockchain().last_block.block_hash): "
                          + str(block_manager.get_blockchain().last_block.header.hash.hex()))
            logging.debug("getstatus block hash(block_manager.get_blockchain().block_height): "
                          + str(block_manager.get_blockchain().block_height))
            logging.debug("getstatus block height: " + str(block_height))
            # Score와 상관없이 TransactionTx는 블럭매니저가 관리 합니다.
            total_tx = block_manager.get_total_tx()

        status_data["status"] = block_manager.service_status
        status_data["state"] = self._channel_service.state_machine.state
        status_data["peer_type"] = str(block_manager.peer_type)
        status_data["audience_count"] = "0"
        status_data["consensus"] = str(conf.CONSENSUS_ALGORITHM.name)
        status_data["peer_id"] = str(ChannelProperty().peer_id)
        status_data["block_height"] = block_height
        status_data["total_tx"] = total_tx
        status_data["unconfirmed_tx"] = block_manager.get_count_of_unconfirmed_tx()
        status_data["peer_target"] = ChannelProperty().peer_target
        status_data["leader_complaint"] = 1

        return status_data

    @message_queue_task
    def create_tx(self, data):
        tx = Transaction()
        score_id = ""
        score_version = ""

        try:
            score_info = self._channel_service.score_info
            score_id = score_info[message_code.MetaParams.ScoreInfo.score_id]
            score_version = score_info[message_code.MetaParams.ScoreInfo.score_version]
        except KeyError as e:
            logging.debug(f"CreateTX : load score info fail\n"
                          f"cause : {e}")

        send_tx_type = self._channel_service.get_channel_option()["send_tx_type"]
        tx.init_meta(ChannelProperty().peer_id, score_id, score_version, ChannelProperty().name, send_tx_type)
        tx.put_data(data)
        tx.sign_hash(self._channel_service.peer_auth)

        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.CREATE_TX, tx)

        try:
            data_log = json.loads(data)
        except Exception as e:
            data_log = {'tx_hash': tx.tx_hash}

        util.apm_event(ChannelProperty().peer_id, {
            'event_type': 'CreateTx',
            'peer_id': ChannelProperty().peer_id,
            'peer_name': conf.PEER_NAME,
            'channel_name': ChannelProperty().name,
            'tx_hash': tx.tx_hash,
            'data': data_log})

        return tx.tx_hash

    @message_queue_task
    async def create_icx_tx(self, kwargs: dict):
        result_code = None
        exception = None
        tx = None

        try:
            tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner
            tx_version = tx_versioner.get_version(kwargs)

            ts = TransactionSerializer.new(tx_version, tx_versioner)
            tx = ts.from_(kwargs)

            tv = TransactionVerifier.new(tx_version, tx_versioner)
            tv.verify(tx)

            block_manager = self._channel_service.block_manager
            block_manager.pre_validate(tx)

            logging.debug(f"create icx input : {kwargs}")

            self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.CREATE_TX, (tx, tx_versioner))
            return message_code.Response.success, tx.hash.hex()

        except TransactionInvalidError as e:
            result_code = e.message_code
            exception = e
            traceback.print_exc()
        except BaseException as e:
            result_code = TransactionInvalidError.message_code
            exception = e
            traceback.print_exc()
        finally:
            if exception:
                logging.warning(f"create_icx_tx: tx restore fail.\n\n"
                                f"kwargs({kwargs})\n\n"
                                f"tx({tx})\n\n"
                                f"exception({exception})")
                return result_code, None

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_tx(self, request) -> None:
        tx_json = request.tx_json

        tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner
        tx_version = tx_versioner.get_version(tx_json)

        ts = TransactionSerializer.new(tx_version, tx_versioner)
        tx = ts.from_(tx_json)

        tv = TransactionVerifier.new(tx_version, tx_versioner)
        tv.verify(tx)

        object_has_queue = self._channel_service.get_object_has_queue_by_consensus()
        if tx is not None:
            object_has_queue.add_tx_obj(tx)
            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'AddTx',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {'tx_hash': tx.tx_hash}})


    @message_queue_task
    def get_tx(self, tx_hash):
        return self._channel_service.block_manager.get_tx(tx_hash)

    @message_queue_task
    def get_tx_info(self, tx_hash):
        tx = self._channel_service.block_manager.get_tx_queue().get(tx_hash, None)
        if tx:
            blockchain = self._channel_service.block_manager.get_blockchain()
            tx_serializer = TransactionSerializer.new(tx.version, blockchain.tx_versioner)
            tx_origin = tx_serializer.to_origin_data(tx)

            logging.info(f"get_tx_info pending : tx_hash({tx_hash})")
            tx_info = dict()
            tx_info["transaction"] = tx_origin
            tx_info["tx_index"] = None
            tx_info["block_height"] = None
            tx_info["block_hash"] = None
            return message_code.Response.success, tx_info
        else:
            try:
                return message_code.Response.success, self._channel_service.block_manager.get_tx_info(tx_hash)
            except KeyError as e:
                logging.error(f"get_tx_info error : tx_hash({tx_hash}) not found error({e})")
                response_code = message_code.Response.fail_invalid_key_error
                return response_code, None

    @message_queue_task(type_=MessageQueueType.Worker)
    async def announce_unconfirmed_block(self, block_pickled) -> None:
        unconfirmed_block = util.block_loads(block_pickled)

        logging.debug(f"#block \n"
                      f"peer_id({unconfirmed_block.header.peer_id.hex()})\n"
                      f"height({unconfirmed_block.header.height})\n"
                      f"hash({unconfirmed_block.header.hash.hex()})")

        self._channel_service.block_manager.add_unconfirmed_block(unconfirmed_block)
        self._channel_service.state_machine.vote()

        is_vote_block = not conf.ALLOW_MAKE_EMPTY_BLOCK and len(unconfirmed_block.body.transactions) == 0
        if is_vote_block:
            util.logger.spam(f"channel_inner_service:AnnounceUnconfirmedBlock try self.peer_service.reset_leader"
                             f"\nnext_leader_peer({unconfirmed_block.header.next_leader.hex()}, "
                             f"channel({ChannelProperty().name}))")

            if ChannelProperty().peer_id == unconfirmed_block.header.next_leader.hex_hx():
                await self._channel_service.reset_leader(unconfirmed_block.header.next_leader.hex_hx())

    @message_queue_task
    async def announce_confirmed_block(self, serialized_block, commit_state="{}"):
        try:
            blockchain = self._channel_service.block_manager.get_blockchain()
            json_block = json.loads(serialized_block)

            block_height = blockchain.block_versioner.get_height(json_block)
            block_version = blockchain.block_versioner.get_version(block_height)
            bs = BlockSerializer.new(block_version, blockchain.tx_versioner)

            confirmed_block = bs.deserialize(json_block)
            util.logger.spam(f"channel_inner_service:announce_confirmed_block\n "
                             f"hash({confirmed_block.header.hash.hex()}) "
                             f"block height({confirmed_block.header.height}), "
                             f"commit_state({commit_state})")

            header: blocks.v0_1a.BlockHeader = confirmed_block.header
            if not header.commit_state:
                bb = BlockBuilder.from_new(confirmed_block, blockchain.tx_versioner)
                confirmed_block = bb.build()  # to generate commit_state
                header = confirmed_block.header
            try:
                commit_state = ast.literal_eval(commit_state)
            except Exception as e:
                logging.warning(f"channel_inner_service:announce_confirmed_block FAIL get commit_state_dict, "
                                f"error by : {e}")

            if header.commit_state != commit_state:
                raise RuntimeError(f"Commit states does not match. "
                                   f"Generated {header.commit_state}, Received {commit_state}")

            if self._channel_service.block_manager.get_blockchain().block_height < confirmed_block.header.height:
                self._channel_service.block_manager.add_confirmed_block(confirmed_block)
            else:
                logging.debug(f"channel_inner_service:announce_confirmed_block "
                              f"already synced block height({confirmed_block.header.height})")
            response_code = message_code.Response.success
        except Exception as e:
            logging.error(f"announce confirmed block error : {e}")
            response_code = message_code.Response.fail
        return response_code

    @message_queue_task
    def announce_new_block_for_vote(self, block: Block, epoch: Epoch):
        acceptor = self._channel_service.acceptor
        if acceptor.epoch is None:
            pass
        else:
            acceptor.epoch.block_hash = block.header.hash.hex()
            acceptor.create_vote(block=block, epoch=epoch)

    @message_queue_task
    def block_sync(self, block_hash, block_height):
        blockchain = self._channel_service.block_manager.get_blockchain()

        response_message = None
        block: Block = None
        if block_hash != "":
            block = blockchain.find_block_by_hash(block_hash)
        elif block_height != -1:
            block = blockchain.find_block_by_height(block_height)
        else:
            response_message = message_code.Response.fail_not_enough_data

        if block is None:
            if response_message is None:
                response_message = message_code.Response.fail_wrong_block_hash

            return response_message, -1, blockchain.block_height, None

        logging.info(f"block header : {block.header}")

        block_dumped = util.block_dumps(block)
        return message_code.Response.success, block.header.height, blockchain.block_height, block_dumped

    @message_queue_task(type_=MessageQueueType.Worker)
    def block_height_sync(self):
        self._channel_service.state_machine.block_sync()

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_audience(self, peer_target) -> None:
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_target)

    @message_queue_task(type_=MessageQueueType.Worker)
    def remove_audience(self, peer_target) -> None:
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.UNSUBSCRIBE, peer_target)

    @message_queue_task(type_=MessageQueueType.Worker)
    def announce_new_peer(self, peer_object_pickled, peer_target) -> None:
        peer_object = pickle.loads(peer_object_pickled)
        logging.debug("Add New Peer: " + str(peer_object.peer_id))

        peer_manager = self._channel_service.peer_manager
        peer_manager.add_peer(peer_object)
        # broadcast the new peer to the others for adding an audience
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_target)

        logging.debug("Try save peer list...")
        self._channel_service.save_peer_manager(peer_manager)
        self._channel_service.show_peers()

        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            quorum, complain_quorum = peer_manager.get_quorum()
            self._channel_service.consensus.set_quorum(quorum=quorum, complain_quorum=complain_quorum)

    @message_queue_task(type_=MessageQueueType.Worker)
    def delete_peer(self, peer_id, group_id) -> None:
        self._channel_service.peer_manager.remove_peer(peer_id, group_id)

    @message_queue_task(type_=MessageQueueType.Worker)
    def vote_unconfirmed_block(self, peer_id, group_id, block_hash: Hash32, vote_code) -> None:
        block_manager = self._channel_service.block_manager
        util.logger.spam(f"channel_inner_service:VoteUnconfirmedBlock "
                         f"({ChannelProperty().name}) block_hash({block_hash})")

        if conf.CONSENSUS_ALGORITHM != conf.ConsensusAlgorithm.lft:
            if self._channel_service.state_machine.state == "Vote":
                # util.logger.warning(f"peer_outer_service:VoteUnconfirmedBlock "
                #                     f"({ChannelProperty().name}) Not Leader Peer!")
                return

        logging.info("Peer vote to : " + block_hash.hex() + " " + str(vote_code) + f"from {peer_id}")

        self._channel_service.block_manager.candidate_blocks.add_vote(
            block_hash,
            group_id,
            peer_id,
            (False, True)[vote_code == message_code.Response.success_validate_block]
        )

        consensus = block_manager.consensus_algorithm
        if isinstance(consensus, ConsensusSiever) and self._channel_service.state_machine.state == "BlockGenerate":
            consensus.count_votes(block_hash)

    @message_queue_task
    async def broadcast_vote(self, vote: VoteMessage):
        acceptor = self._channel_service.acceptor
        if acceptor.epoch is None:
            pass
        else:
            await acceptor.apply_vote_into_block(vote)

    @message_queue_task
    def get_invoke_result(self, tx_hash):
        try:
            invoke_result = self._channel_service.block_manager.get_invoke_result(tx_hash)
            invoke_result_str = json.dumps(invoke_result)
            response_code = message_code.Response.success
            logging.debug('invoke_result : ' + invoke_result_str)

            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'GetInvokeResult',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {'invoke_result': invoke_result, 'tx_hash': tx_hash}})

            if 'code' in invoke_result:
                if invoke_result['code'] == ScoreResponse.NOT_EXIST:
                    logging.debug(f"get invoke result NOT_EXIST tx_hash({tx_hash})")
                    response_code = message_code.Response.fail_invalid_key_error
                elif invoke_result['code'] == ScoreResponse.NOT_INVOKED:
                    logging.info(f"get invoke result NOT_INVOKED tx_hash({tx_hash})")
                    response_code = message_code.Response.fail_tx_not_invoked

            return response_code, invoke_result_str
        except BaseException as e:
            logging.error(f"get invoke result error : {e}")
            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'Error',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {
                    'error_type': 'InvokeResultError',
                    'code': message_code.Response.fail,
                    'message': f"get invoke result error : {e}"}})
            return message_code.Response.fail, None

    @message_queue_task
    async def get_block_v2(self, block_height, block_hash, block_data_filter, tx_data_filter):
        # This is a temporary function for v2 support of exchanges.
        block, block_filter, block_hash, fail_response_code, tx_filter = await self.__get_block(
            block_data_filter, block_hash, block_height, tx_data_filter)
        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({}), ""

        tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner
        bs = BlockSerializer.new(block.header.version, tx_versioner)
        block_data_dict = bs.serialize(block)

        if block.header.height == 0:
            return message_code.Response.success, block_hash, json.dumps(block_data_dict), []

        confirmed_tx_list = block_data_dict["confirmed_transaction_list"]
        confirmed_tx_list_without_fail = []

        tss = {
            "genesis": TransactionSerializer.new("genesis", tx_versioner),
            "0x2": TransactionSerializer.new("0x2", tx_versioner),
            "0x3": TransactionSerializer.new("0x3", tx_versioner)
        }

        for tx in confirmed_tx_list:
            version = tx_versioner.get_version(tx)
            tx_hash = tss[version].get_hash(tx)

            invoke_result = self._channel_service.block_manager.get_invoke_result(tx_hash)

            if 'failure' in invoke_result:
                continue

            if tx_versioner.get_version(tx) == "0x3":
                step_used, step_price = int(invoke_result["stepUsed"], 16), int(invoke_result["stepPrice"], 16)
                tx["fee"] = hex(step_used * step_price)

            confirmed_tx_list_without_fail.append(tx)

        # Replace the existing confirmed_tx_list with v2 ver.
        block_data_dict["confirmed_transaction_list"] = confirmed_tx_list_without_fail
        block_data_json = json.dumps(block_data_dict)

        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({}), []

        return message_code.Response.success, block_hash, block_data_json, []

    @message_queue_task
    async def get_block(self, block_height, block_hash, block_data_filter, tx_data_filter):
        block, block_filter, block_hash, fail_response_code, tx_filter = await self.__get_block(
            block_data_filter, block_hash, block_height, tx_data_filter)

        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({}), ""

        tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner
        bs = BlockSerializer.new(block.header.version, tx_versioner)
        block_dict = bs.serialize(block)
        return message_code.Response.success, block_hash, json.dumps(block_dict), []

    async def __get_block(self, block_data_filter, block_hash, block_height, tx_data_filter):
        block_manager = self._channel_service.block_manager
        if block_hash == "" and block_height == -1:
            block_hash = block_manager.get_blockchain().last_block.header.hash.hex()
        block_filter = re.sub(r'\s', '', block_data_filter).split(",")
        tx_filter = re.sub(r'\s', '', tx_data_filter).split(",")

        block = None
        fail_response_code = None
        if block_hash:
            block = block_manager.get_blockchain().find_block_by_hash(block_hash)
            if block is None:
                fail_response_code = message_code.Response.fail_wrong_block_hash
        elif block_height != -1:
            block = block_manager.get_blockchain().find_block_by_height(block_height)
            if block is None:
                fail_response_code = message_code.Response.fail_wrong_block_height
        else:
            fail_response_code = message_code.Response.fail_wrong_block_hash

        return block, block_filter, block_hash, fail_response_code, tx_filter

    @message_queue_task
    def get_precommit_block(self, last_block_height: int):
        block_manager = self._channel_service.block_manager
        precommit_block = block_manager.get_blockchain().get_precommit_block()

        if precommit_block is None:
            return message_code.Response.fail, "there is no precommit block.", b""
        if precommit_block.height != last_block_height + 1:
            return message_code.Response.fail, "need block height sync.", b""

        return message_code.Response.success, "success", pickle.dumps(precommit_block)

    @message_queue_task
    def get_tx_by_address(self, address, index):
        block_manager = self._channel_service.block_manager
        tx_list, next_index = block_manager.get_blockchain().get_tx_list_by_address(address=address, index=index)

        return tx_list, next_index

    @message_queue_task
    def get_score_status(self):
        score_status = ""
        try:
            score_status_response = self._channel_service.score_stub.call(
                "Request",
                loopchain_pb2.Message(code=message_code.Request.status)
            )

            logging.debug("Get Score Status : " + str(score_status_response))

        except Exception as e:
            logging.debug("Score Service Already stop by other reason. %s", e)

        else:
            if score_status_response.code == message_code.Response.success:
                score_status = score_status_response.meta

        return score_status

    @message_queue_task
    def reset_timer(self, key):
        self._channel_service.timer_service.reset_timer(key)

    @message_queue_task(type_=MessageQueueType.Worker)
    def stop(self, message):
        logging.info(f"channel_inner_service:stop message({message})")
        self._channel_service.close()


class ChannelInnerService(MessageQueueService[ChannelInnerTask]):
    TaskType = ChannelInnerTask

    def __init__(self, amqp_target, route_key, username=None, password=None, **task_kwargs):
        super().__init__(amqp_target, route_key, username, password, **task_kwargs)
        self._task._citizen_condition_new_block = Condition(loop=self.loop)

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")

    def notify_new_block(self):

        async def _notify():
            condition = self._task._citizen_condition_new_block
            async with condition:
                condition.notify_all()

        asyncio.run_coroutine_threadsafe(_notify(), self.loop)

    def init_sub_services(self):
        if self.loop != asyncio.get_event_loop():
            raise Exception("Must call this function in thread of self.loop")
        self._task.init_sub_service(self.loop)

    def cleanup(self):
        if self.loop != asyncio.get_event_loop():
            raise Exception("Must call this function in thread of self.loop")
        self._task.cleanup_sub_services()


class ChannelInnerStub(MessageQueueStub[ChannelInnerTask]):
    TaskType = ChannelInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")
