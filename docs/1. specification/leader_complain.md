# Leader Complain

#### Terms
 * Height
   - Increase after add block when consensus complete.
 * Inning
   - Increase when next leader elected in same height.
 * Round
   - round 0 is first block generation try of each height.
   - If leader fail to make a block, round n is to be leader complain round.
 * Strategy
   - leader pick strategy in round n. (normal strategy)
     - pick most picked peer in prev round.
 
#### Complain Process
  * heartbeat
    - before 'Vote'
      - Change state to 'LeaderComplain' when there is no 'AnnounceUnconfirmedBlock' in block interval.
  * broadcast leader complain
    - broadcast leader complain message (contains prev_leader, next_leader, prev_time_interval)
    - If receive 'AnnounceUnconfirmedBlock' in state 'LeaderComplain' then Peer should not vote.
  * Increase block generate time interval
    - After each leader complain phase, next leader get more *2 time interval than prev leader.
    

#### Complain message
  ```
  {
    block_hash
    height  
    prev_leader
    next_leader
    prev_interval
  }
  ```    

#### 7 Peer Simulation.
  1. Height = x
  
    - Inning = 0 
      - Round = 0
        - wait Vote for unconfirmed block.
        - Vote Slot [], [], [], [], [], [], []
        - When firt vote finished [v], [v], [v], [v], [c], [c], [c] (v: Vote, c: Complain)
        - Enter leader complain round
        
      - Round = 1
        - wait complain message 
        - When complain finished [c], [c], [c], [c], [c], [c], [c] (v: Vote, c: Complain)
        - If there is 1/2 + 1 same pick for next leader, leader complain round finished, start next Inning in same height.
        - If there is not, start next round with 'normal strategy'

        - Round up condition
          - All normal peers repeat the round Complain Message if the round is not completed.
          - If round voting is completed or leader selection is not possible, round is going up.
        
    - Inning = 1
      - Round = 0
        - Leader get ( init_interval ** (inning + 1) ) time interval.
        - wait Vote for unconfirmed block (made by new leader)
 