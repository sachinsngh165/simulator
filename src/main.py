from core.peer_dbs import Peer_DBS
from core.monitor_dbs import Monitor_DBS
from core.splitter_dbs import Splitter_DBS
import time

splitter = Splitter_DBS()
splitter.start()

#peer = Peer_DBS()
peer = Monitor_DBS("M1")
peer.set_splitter(splitter)
peer.connect_to_the_splitter()
peer.receive_the_number_of_peers()
peer.receive_the_list_of_peers()
print("number of peers", len(peer.peer_list))
peer.send_ready_for_receiving_chunks()
peer.buffer_data()
peer.start()


time.sleep(5)

peer = Peer_DBS("P1")
peer.set_splitter(splitter)
peer.connect_to_the_splitter()
peer.receive_the_number_of_peers()
peer.receive_the_list_of_peers()
print("number of peers", len(peer.peer_list))
peer.send_ready_for_receiving_chunks()
peer.buffer_data()
peer.start()

        

        