use std::collections::{BTreeMap, BTreeSet};

use crate::Item;

pub struct CycleDetector<'a> {
    all_items: &'a BTreeMap<String, Item>,
    visited_items: BTreeSet<String>,
    visiting_items: BTreeSet<String>,
    cyclic_items: BTreeSet<String>,
}

impl CycleDetector<'_> {
    pub fn cycle_detect(all_items: &BTreeMap<String, Item>) -> BTreeSet<String> {
        let mut detector = CycleDetector {
            all_items,
            visited_items: BTreeSet::new(),
            visiting_items: BTreeSet::new(),
            cyclic_items: BTreeSet::new(),
        };

        for (name, item) in all_items {
            if item.needed {
                detector.visit_item(name);
            }
        }

        return detector.cyclic_items;
    }

    fn visit_item(&mut self, name: &str) {
        if self.visited_items.contains(name) {
            return;
        }

        if self.visiting_items.contains(name) {
            // CYCLE DETECTED!
            self.cyclic_items.insert(name.to_string());
            self.visited_items.insert(name.to_string());
            return;
        }

        if let Some(item) = &self.all_items.get(name) {
            self.visiting_items.insert(name.to_string());
            for dep in &item.deps {
                self.visit_item(dep);
            }
            self.visited_items.remove(name);
        }
        self.visited_items.insert(name.to_string());
    }
}
