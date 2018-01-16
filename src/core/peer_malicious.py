"""
@package simulator
peer_malicious module
"""

from .simulator_stuff import Simulator_stuff as sim
from .peer_strpeds import Peer_STRPEDS
import random


class Peer_Malicious(Peer_STRPEDS):

    def __init__(self, id):
        super().__init__(id)
        self.MPTR = 3
        self.ATTACK_METHOD = 1
        self.chunks_sent_to_main_target = 0
        self.persistent_attack = True
        self.attacked_count = 0
        self.recv_counter = 0
        sim.SHARED_LIST["malicious"].append(self.id)
        random.seed(3)
        print("Peer Malicious initialized")

    def receive_the_list_of_peers(self):
        Peer_STRPEDS.receive_the_list_of_peers(self)
        self.first_main_target()

    def first_main_target(self):
        self.main_target = self.choose_main_target()

    def choose_main_target(self):
        #return self.selection_first_method()
        return self.selection_second_method()

    def selection_first_method(self):
        target = None
        malicious_list = sim.SHARED_LIST["malicious"]
        extra_attacks = len(set(self.peer_list) & set(sim.SHARED_LIST["regular"]))
        if (self.attacked_count + extra_attacks) < (int(len(self.peer_list)*1) - len(malicious_list)):
            attacked_list = sim.SHARED_LIST["attacked"]
            availables = list(set(self.peer_list)-set(attacked_list)-set(malicious_list))

            if availables:
                target = random.choice(availables)
                sim.SHARED_LIST["attacked"].append(target)
                if __debug__:
                    print("Main target selected:", target)
                self.chunks_sent_to_main_target = 0
                self.attacked_count += 1

        return target

    def selection_second_method(self):
        target = None
        malicious_list = sim.SHARED_LIST["malicious"]
        extra_attacks = len(set(self.peer_list) & set(sim.SHARED_LIST["regular"]))
        if (self.attacked_count + extra_attacks) < (int(len(self.peer_list)*1) - len(malicious_list)):
            attacked_list = sim.SHARED_LIST["attacked"]
            quarantine_list = sim.SHARED_LIST["quarantine"].keys()
            availables = list(set(self.peer_list)-set(attacked_list)-set(malicious_list)-set(quarantine_list))

            if availables:
                target = random.choice(availables)
            else:
                potentials_wip_list = [k for k, v in sim.SHARED_LIST["quarantine"].items() if v == min(sim.SHARED_LIST["quarantine"].values())]
                target = random.choice(potentials_wip_list)

            if target is not None:
                sim.SHARED_LIST["attacked"].append(target)
                if __debug__:
                    print("Main # TODO: arget selected:", target)
                self.chunks_sent_to_main_target = 0
                self.attacked_count += 1

        return target

    def all_attack(self):
        if __debug__:
            print("All attack mode")
        sim.SHARED_LIST["regular"].append(self.main_target)

    def get_poisoned_chunk(self, chunk):
        return (chunk[0], "B", chunk[2])

    def process_message(self, message, sender):
        if sender != self.splitter:
            self.recv_counter += 1
            if self.recv_counter > (len(self.peer_list)-self.attacked_count):  # it is out
                for peer in sim.SHARED_LIST["regular"]:
                    if peer in sim.SHARED_LIST["quarantine"]:
                        sim.SHARED_LIST["quarantine"][peer] = sim.SHARED_LIST["quarantine"][peer] + (1/len(sim.SHARED_LIST["regular"]))
                    else:
                        sim.SHARED_LIST["quarantine"][peer] = 1/len(sim.SHARED_LIST["regular"])
                print(self.id, "Discover?")
                sim.SHARED_LIST["regular"][:] = []
        else:
            self.recv_counter = 0
            
        return Peer_STRPEDS.process_message(self, message, sender)

    def send_chunk(self, peer):
        poisoned_chunk = self.get_poisoned_chunk(self.receive_and_feed_previous)
        
        if self.persistent_attack:
            if peer == self.main_target:
                if self.chunks_sent_to_main_target < self.MPTR:
                    self.team_socket.sendto("isi", poisoned_chunk, peer)
                    self.sendto_counter += 1
                    self.chunks_sent_to_main_target += 1
                    if __debug__:
                        print(self.id, "Attacking Main target", self.main_target, "attack", self.chunks_sent_to_main_target)
                else:
                    self.all_attack()
                    self.team_socket.sendto("isi", poisoned_chunk, peer)
                    self.sendto_counter += 1
                    self.main_target = self.choose_main_target()
                    if __debug__:
                        print(self.id, "Attacking Main target", peer, ". Replaced by", self.main_target)
            else:
                if peer in sim.SHARED_LIST["regular"]:
                    self.team_socket.sendto("isi", poisoned_chunk, peer)
                    self.sendto_counter += 1
                    if __debug__:
                        print(self.id, "All Attack:", peer)
                else:
                    self.team_socket.sendto("isi", self.receive_and_feed_previous, peer)
                    self.sendto_counter += 1
                    if __debug__:
                        print(self.id, "No attack", peer)

            if self.main_target is None:
                self.main_target = self.choose_main_target()

        else:
            self.team_socket.sendto("isi", self.receive_and_feed_previous, peer)
            self.sendto_counter += 1
