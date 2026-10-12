//! Keeps track of in-flight client connections.
//!
//! When the table is full, a new connection replaces an old one from the
//! busiest part of the address space.
//! A host or a network flooding the server mostly replaces its own connections.

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;

const NONE: u32 = u32::MAX;

#[derive(Debug)]
struct Slot<T> {
    value: Option<T>,
    leaf: u32,
    prev: u32,
    next: u32,
}

#[derive(Debug)]
enum Node {
    Branch {
        bit: u32,
        children: [u32; 2],
        count: u32,
    },
    Leaf {
        key: u128,
        oldest: u32,
        newest: u32,
        count: u32,
    },
}

#[derive(Debug)]
pub struct ConnectionSlots<T> {
    slots: Vec<Slot<T>>,
    free_slots: Vec<u32>,
    nodes: Vec<Node>,
    free_nodes: Vec<u32>,
    root: u32,
    max_active: u32,
}

/// Frees the connection's slot when dropped.
pub struct SlotGuard<T> {
    table: Arc<Mutex<ConnectionSlots<T>>>,
    index: u32,
}

impl<T> Drop for SlotGuard<T> {
    fn drop(&mut self) {
        self.table.lock().remove(self.index);
    }
}

fn ip_key(ip: IpAddr) -> u128 {
    let ip = match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    u128::from(ip)
}

fn bit_at(key: u128, bit: u32) -> usize {
    ((key >> (127 - bit)) & 1) as usize
}

impl<T> ConnectionSlots<T> {
    /// Creates a table for `max_active` connections.
    ///
    /// Replaced connections hold on to their slot until they stop.
    /// There is room for `max_active` of those as well.
    pub fn new(max_active: usize) -> Self {
        let max_active = max_active.clamp(1, (NONE / 4) as usize);
        let capacity = max_active * 2;
        let slots = (0..capacity)
            .map(|_| Slot {
                value: None,
                leaf: NONE,
                prev: NONE,
                next: NONE,
            })
            .collect();
        ConnectionSlots {
            slots,
            free_slots: (0..capacity as u32).rev().collect(),
            nodes: Vec::with_capacity(max_active * 2 - 1),
            free_nodes: Vec::new(),
            root: NONE,
            max_active: max_active as u32,
        }
    }

    /// Adds a connection from `ip`, replacing an older one if the table is full.
    /// The value of the replaced connection is dropped.
    ///
    /// Returns `None` if too many replaced connections are still running.
    pub fn register(table: &Arc<Mutex<Self>>, ip: IpAddr, value: T) -> Option<SlotGuard<T>> {
        let index = table.lock().insert(ip, value)?;
        Some(SlotGuard {
            table: table.clone(),
            index,
        })
    }

    /// Evicts the oldest connection in the busiest part of the address space,
    /// and drops its value.
    pub fn evict_busiest(&mut self) -> bool {
        if self.root == NONE {
            return false;
        }
        let mut node = self.root;
        let oldest = loop {
            match self.nodes[node as usize] {
                Node::Branch {
                    children: [left, right],
                    ..
                } => {
                    node = if self.count(right) > self.count(left) {
                        right
                    } else {
                        left
                    };
                }
                Node::Leaf { oldest, .. } => break oldest,
            }
        };
        self.unlink(oldest);
        true
    }

    fn insert(&mut self, ip: IpAddr, value: T) -> Option<u32> {
        let index = self.free_slots.pop()?;
        if self.root != NONE && self.count(self.root) == self.max_active {
            self.evict_busiest();
        }
        let leaf = self.attach(ip_key(ip));
        let Node::Leaf {
            oldest,
            newest,
            count,
            ..
        } = &mut self.nodes[leaf as usize]
        else {
            unreachable!()
        };
        if *newest == NONE {
            *oldest = index;
        } else {
            self.slots[*newest as usize].next = index;
        }
        let prev = *newest;
        *newest = index;
        *count += 1;
        self.slots[index as usize] = Slot {
            value: Some(value),
            leaf,
            prev,
            next: NONE,
        };
        Some(index)
    }

    fn remove(&mut self, index: u32) {
        if self.slots[index as usize].leaf != NONE {
            self.unlink(index);
        }
        self.free_slots.push(index);
    }

    fn unlink(&mut self, index: u32) {
        let slot = &mut self.slots[index as usize];
        slot.value = None;
        let (leaf, prev, next) = (slot.leaf, slot.prev, slot.next);
        slot.leaf = NONE;
        let Node::Leaf {
            key,
            oldest,
            newest,
            count,
        } = &mut self.nodes[leaf as usize]
        else {
            unreachable!()
        };
        if prev == NONE {
            *oldest = next;
        } else {
            self.slots[prev as usize].next = next;
        }
        if next == NONE {
            *newest = prev;
        } else {
            self.slots[next as usize].prev = prev;
        }
        *count -= 1;
        let (key, now_empty) = (*key, *count == 0);
        self.detach(key, now_empty);
    }

    /// Returns the leaf for `key`, creating it if needed.
    /// The caller still has to add the connection to the leaf.
    fn attach(&mut self, key: u128) -> u32 {
        if self.root == NONE {
            self.root = self.alloc_leaf(key);
            return self.root;
        }
        let common_bits = (key ^ self.best_match_key(key)).leading_zeros();
        let (mut parent, mut side) = (NONE, 0);
        let mut node = self.root;
        while let Node::Branch {
            bit,
            children,
            count,
        } = &mut self.nodes[node as usize]
        {
            if *bit >= common_bits {
                break;
            }
            *count += 1;
            parent = node;
            side = bit_at(key, *bit);
            node = children[side];
        }
        if common_bits == u128::BITS {
            return node;
        }
        let leaf = self.alloc_leaf(key);
        let mut children = [node; 2];
        children[bit_at(key, common_bits)] = leaf;
        let branch = self.alloc_node(Node::Branch {
            bit: common_bits,
            children,
            count: self.count(node) + 1,
        });
        self.set_child(parent, side, branch);
        leaf
    }

    fn detach(&mut self, key: u128, remove_leaf: bool) {
        let (mut grandparent, mut parent_side) = (NONE, 0);
        let (mut parent, mut side) = (NONE, 0);
        let mut node = self.root;
        while let Node::Branch {
            bit,
            children,
            count,
        } = &mut self.nodes[node as usize]
        {
            *count -= 1;
            (grandparent, parent_side) = (parent, side);
            parent = node;
            side = bit_at(key, *bit);
            node = children[side];
        }
        if !remove_leaf {
            return;
        }
        self.free_nodes.push(node);
        if parent == NONE {
            self.root = NONE;
            return;
        }
        let Node::Branch { children, .. } = self.nodes[parent as usize] else {
            unreachable!()
        };
        self.free_nodes.push(parent);
        self.set_child(grandparent, parent_side, children[1 - side]);
    }

    /// Returns the key of a leaf sharing the longest common prefix with `key`.
    fn best_match_key(&self, key: u128) -> u128 {
        let mut node = self.root;
        loop {
            match self.nodes[node as usize] {
                Node::Branch { bit, children, .. } => node = children[bit_at(key, bit)],
                Node::Leaf { key, .. } => return key,
            }
        }
    }

    fn count(&self, node: u32) -> u32 {
        match self.nodes[node as usize] {
            Node::Branch { count, .. } | Node::Leaf { count, .. } => count,
        }
    }

    fn set_child(&mut self, parent: u32, side: usize, child: u32) {
        if parent == NONE {
            self.root = child;
        } else if let Node::Branch { children, .. } = &mut self.nodes[parent as usize] {
            children[side] = child;
        }
    }

    fn alloc_leaf(&mut self, key: u128) -> u32 {
        self.alloc_node(Node::Leaf {
            key,
            oldest: NONE,
            newest: NONE,
            count: 0,
        })
    }

    fn alloc_node(&mut self, node: Node) -> u32 {
        match self.free_nodes.pop() {
            Some(index) => {
                self.nodes[index as usize] = node;
                index
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    impl<T: Copy> ConnectionSlots<T> {
        fn values(&self) -> Vec<T> {
            self.slots.iter().filter_map(|slot| slot.value).collect()
        }

        /// Returns the number of connections below `node`, and the key of one
        /// of its leaves.
        fn check_subtree(&self, node: u32, min_bit: u32) -> (u32, u128) {
            match self.nodes[node as usize] {
                Node::Branch {
                    bit,
                    children,
                    count,
                } => {
                    assert!(bit >= min_bit);
                    let (left_count, left_key) = self.check_subtree(children[0], bit + 1);
                    let (right_count, right_key) = self.check_subtree(children[1], bit + 1);
                    assert_eq!((left_key ^ right_key).leading_zeros(), bit);
                    assert_eq!(bit_at(left_key, bit), 0);
                    assert_eq!(count, left_count + right_count);
                    (count, left_key)
                }
                Node::Leaf {
                    key,
                    oldest,
                    newest,
                    count,
                } => {
                    let mut seen = 0;
                    let (mut prev, mut index) = (NONE, oldest);
                    while index != NONE {
                        let slot = &self.slots[index as usize];
                        assert_eq!(slot.leaf, node);
                        assert_eq!(slot.prev, prev);
                        assert!(slot.value.is_some());
                        (prev, index) = (index, slot.next);
                        seen += 1;
                    }
                    assert_eq!(prev, newest);
                    assert!(count > 0);
                    assert_eq!(count, seen);
                    (count, key)
                }
            }
        }

        fn check_invariants(&self) {
            let active = self.slots.iter().filter(|slot| slot.leaf != NONE).count();
            let total = match self.root {
                NONE => 0,
                root => self.check_subtree(root, 0).0,
            };
            assert_eq!(total as usize, active);
            let live_nodes = self.nodes.len() - self.free_nodes.len();
            assert!(live_nodes <= (2 * active).saturating_sub(1));
        }
    }

    #[test]
    fn test_replaces_oldest_connection_on_busiest_side() {
        let mut slots = ConnectionSlots::new(7);
        for value in 1..=3 {
            slots.insert(IpAddr::from([10, 0, 0, 1]), value);
        }
        slots.insert(IpAddr::from([100, 0, 0, 1]), 4);
        slots.insert(IpAddr::from([100, 0, 0, 1]), 5);
        slots.insert(IpAddr::from([100, 0, 0, 2]), 6);
        slots.insert(IpAddr::from([127, 0, 0, 1]), 7);
        // 10.0.0.1 has the most connections, but 64.0.0.0/2 has more than 0.0.0.0/2.
        slots.insert(IpAddr::from([192, 0, 2, 1]), 8);
        assert_eq!(slots.values(), [1, 2, 3, 5, 6, 7, 8]);
    }

    #[test]
    fn test_subnet_flood_only_replaces_its_own_connections() {
        let mut slots = ConnectionSlots::new(16);
        for i in 0..4 {
            slots.insert(IpAddr::from([198, 51, i, 1]), i);
        }
        // 12 queries fill the table, and 16 more replace older ones until all
        // 32 slots are held.
        let held = (0..=255)
            .filter_map(|host| slots.insert(IpAddr::from([198, 51, 100, host]), 100))
            .count();
        assert_eq!(held, 28);
        assert_eq!(slots.values()[..4], [0, 1, 2, 3]);
    }

    #[test]
    fn test_ipv4_and_mapped_ipv6_are_the_same_client() {
        let mut slots = ConnectionSlots::new(2);
        let ip = Ipv4Addr::new(198, 51, 100, 1);
        slots.insert(IpAddr::V4(ip), 1);
        slots.insert(IpAddr::V6(ip.to_ipv6_mapped()), 2);
        assert!(matches!(
            slots.nodes[slots.root as usize],
            Node::Leaf { count: 2, .. }
        ));
    }

    #[test]
    fn test_random_operations_keep_invariants() {
        let mut rng = SmallRng::seed_from_u64(1);
        let mut slots = ConnectionSlots::new(64);
        let mut held = Vec::new();
        for i in 0..20_000 {
            if rng.random_range(0..3) == 0 && !held.is_empty() {
                let index = held.swap_remove(rng.random_range(0..held.len()));
                slots.remove(index);
            } else {
                // Few addresses, so that clients often share prefixes.
                let ip = if rng.random_range(0..4) == 0 {
                    IpAddr::V6(Ipv6Addr::from(rng.random_range(0..32u128)))
                } else {
                    IpAddr::from([10, rng.random_range(0..3), 0, rng.random_range(0..24)])
                };
                held.extend(slots.insert(ip, i));
            }
            if i % 97 == 0 {
                slots.check_invariants();
            }
        }
        for index in held {
            slots.remove(index);
        }
        slots.check_invariants();
        assert_eq!(slots.free_slots.len(), slots.slots.len());
    }
}
