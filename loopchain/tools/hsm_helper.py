import logging

import pkcs11
import pdb
from pkcs11 import Attribute, ObjectClass, Mechanism, KeyType
import os
from loopchain import configure as conf
from loopchain.components import SingletonMetaClass


class HsmHelper(metaclass=SingletonMetaClass):
    """Help Get CertPair and Keys From KMS"""
    def __init__(self):
        """init members using os.environ

        """
        # Load PKCS11 module
        lib = pkcs11.lib(conf.HSM_LIB_PATH)
        # Get token
        self.__token = lib.get_token(token_label=conf.HSM_TOKEN_LABEL)
        self.__agent_pin = None

    def set_agent_pin(self, agent_pin):
        if agent_pin is None:
            self.__agent_pin = conf.HSM_USER_NAME + ":" + conf.HSM_USER_PASSWORD
        else:
            self.__agent_pin = agent_pin

    def remove_agent_pin(self):
        """remove agent_pin for security
        """
        self.__agent_pin = None

    def __get_cert_pair(self, key_id: str) -> (bytes, bytes):
        """get cert pair from kms using key id

        :param key_id: load key id
        :return: (cert_byte, private_key_byte)
        """
        with self.__token.open(rw=True, user_pin=self.__agent_pin) as session:
            secret_key = None
            cert_data = None
            pdb.set_trace()
            try:
                secret_key = next(session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY,
                                                       Attribute.LABEL: conf.HSM_SECRET_KEY_LABEL}))
            except Exception as e:
                logging.exception(e)
                raise CreateSecretKeyException(f"Not found the SecretKey. LABEL: {conf.HSM_SECRET_KEY_LABEL}")

            try:
                private_key = next(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                                                        Attribute.LABEL: key_id}))
            except StopIteration:
                raise PrivateKeyNotFoundException(f"Not Found Private Key! ID : {key_id}")
            except Exception as e:
                logging.exception(e)
                raise GetPrivateKeyException(f"Fail to get private key.")

            # Secret Key로 Private Key 복호화
            pri_key_data = self.__get_raw_data(private_key, secret_key, Mechanism.AES_CBC_PAD)

            # # Public Key 검색
            # try:
            #     cert = self.__get_key_handle(session, ObjectClass.CERTIFICATE, key_id)
            # except StopIteration:
            #     raise CertNotFoundException(f"Cannot Found Certificate! ID : {key_id}")
            # except Exception as e:
            #     logging.exception(e)
            #     raise GetCertKeyException("get certificate fail")
            #
            # # Public Key raw data 저장 (공개키이기 때문에 바로 값 접근 가능)
            # cert_data = cert[Attribute.VALUE]

        return cert_data, pri_key_data

    def get_signature_cert_pair(self, key_id: str) -> (bytes, bytes):
        """get signature cert pair

        :param key_id: kms key_id
        :return: (cert_bytes, private_bytes)
        """

        return self.__get_cert_pair(key_id)

    def get_tls_cert_pair(self) -> (bytes, bytes):
        """get tls cert pair

        :return: (cert_bytes, private_bytes)
        """
        return self.__get_cert_pair(conf.KMS_TLS_KEY_ID)

    # @staticmethod
    # def __get_key_and_cert_data_from_file(key_path, cert_path):
    #     key_data = ""
    #     cert_data = ""
    #     with open(key_path, "rb") as f:
    #         key_data = f.read()
    #
    #     with open(cert_path, "rb") as f:
    #         cert_data = f.read()
    #
    #     return (key_data, cert_data)
    #
    # @staticmethod
    # def __generate_key(session, gen_type, length, key_label):
    #     return session.generate_key(key_type=gen_type,
    #                                 key_length=length,
    #                                 label=key_label)
    #
    # @staticmethod
    # def __get_key_handle(session, key_class, key_label):
    #     return next(session.get_objects({Attribute.CLASS: key_class,
    #                                      Attribute.LABEL: key_label}))
    #
    # @staticmethod
    # def __generate_random(session, random_len):
    #     return session.generate_random(random_len)
    #
    # @staticmethod
    # def __get_encrypted_key_data(wrapped_key, wrapping_key, wrap_mech, iv):
    #     return wrapping_key.wrap_key(wrapped_key, mechanism=wrap_mech, mechanism_param=iv)
    #
    # @staticmethod
    # def __get_raw_data(encrypted_data, decrypt_key, decrypt_mech, iv):
    #     return decrypt_key.decrypt(encrypted_data, mechanism=decrypt_mech, mechanism_param=iv)


class CreateSecretKeyException(Exception):
    """When Raise KMS create SecretKey for private key encryption Fail """
    pass


class PrivateKeyNotFoundException(Exception):
    """When Raise KMS Cannot found PrivateKey"""
    pass


class GetPrivateKeyException(Exception):
    """When Raise KMS Get PrivateKey Fail"""
    pass


class CertNotFoundException(Exception):
    """When Raise KMS Cannot found Certificate"""
    pass


class GetCertKeyException(Exception):
    """When Raise KMS Get Certificate Fail"""
    pass
