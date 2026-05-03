use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::errors::*;

#[derive(Debug)]
struct BlackListInner {
    map: FxHashMap<Vec<u8>, ()>,
}

#[derive(Clone, Debug)]
pub struct BlackList {
    inner: Arc<BlackListInner>,
    max_labels: usize,
}

fn label_count(qname: &[u8]) -> usize {
    if qname.is_empty() {
        0
    } else {
        qname.iter().filter(|&&b| b == b'.').count() + 1
    }
}

impl BlackList {
    pub fn new(map: FxHashMap<Vec<u8>, ()>) -> Self {
        let max_labels = map.keys().map(|k| label_count(k)).max().unwrap_or(0);
        let inner = Arc::new(BlackListInner { map });
        BlackList { inner, max_labels }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut map = FxHashMap::default();
        let fp = BufReader::new(File::open(path)?);
        for (line_nb, line) in fp.lines().enumerate() {
            let line = line?;
            let mut line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            while line.starts_with("*.") {
                line = &line[2..];
            }
            while line.ends_with('.') {
                line = &line[..line.len() - 1];
            }
            let qname = line.as_bytes().to_ascii_lowercase();
            if qname.is_empty() {
                bail!("Unexpected blacklist rule at line {}", line_nb)
            }
            map.insert(qname, ());
        }
        Ok(BlackList::new(map))
    }

    pub fn find(&self, qname: &[u8]) -> bool {
        if self.max_labels == 0 {
            return false;
        }
        let qname = qname.to_ascii_lowercase();
        let mut qname = qname.as_slice();
        let map = &self.inner.map;
        let mut start = 0;
        let mut dots = 0;
        for i in (0..qname.len()).rev() {
            if qname[i] == b'.' {
                dots += 1;
                if dots == self.max_labels {
                    start = i + 1;
                    break;
                }
            }
        }
        qname = &qname[start..];
        while !qname.is_empty() {
            if map.contains_key(qname) {
                return true;
            }
            match qname.iter().position(|&b| b == b'.') {
                Some(pos) => qname = &qname[pos + 1..],
                None => break,
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(entries: &[&str]) -> BlackList {
        let mut map = FxHashMap::default();
        for entry in entries {
            map.insert(entry.as_bytes().to_vec(), ());
        }
        BlackList::new(map)
    }

    #[test]
    fn exact_match() {
        let bl = make(&["evil.example"]);
        assert!(bl.find(b"evil.example"));
    }

    #[test]
    fn suffix_match_single_label() {
        let bl = make(&["evil.example"]);
        assert!(bl.find(b"sub.evil.example"));
    }

    #[test]
    fn deep_subdomain_matches_short_suffix() {
        let bl = make(&["blocked.example"]);
        assert!(bl.find(b"a.b.c.d.e.f.g.h.blocked.example"));
    }

    #[test]
    fn unrelated_name_does_not_match() {
        let bl = make(&["blocked.example"]);
        assert!(!bl.find(b"good.example"));
        assert!(!bl.find(b"a.b.c.good.example"));
    }

    #[test]
    fn parent_of_blocked_is_not_blocked() {
        let bl = make(&["sub.example.com"]);
        assert!(!bl.find(b"example.com"));
        assert!(!bl.find(b"com"));
    }

    #[test]
    fn empty_blacklist() {
        let bl = make(&[]);
        assert!(!bl.find(b"anything.example"));
    }

    #[test]
    fn case_insensitive() {
        let bl = make(&["evil.example"]);
        assert!(bl.find(b"SUB.Evil.EXAMPLE"));
    }
}
