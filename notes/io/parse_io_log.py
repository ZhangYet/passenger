#!/usr/bin/env python3

class NewTreeException(Exception):
    pass


class Node:

    def __init__(self, name: str):
        self.name = name
        self.subnodes = []

    def add_subnode(self, node):
        self.subnodes.append(node)

        
class Tree:

    def __init__(self):
        self.nodes = {}
        self.root = None

    def is_empty(self):
        return not self.root

    def __record_node(self, node: Node):
        self.nodes[node.name] = node

    def merge_chain(self, root_node):
        prev, curr = None, root_node

        while True:
            if curr.name in self.nodes:
                 prev = curr

                 if not curr.subnodes:
                     break

                 curr = curr.subnodes[0]
                 continue

            if prev:
                 self.nodes[prev.name].add_subnode(curr)
            else:
                if not self.is_empty():
                    raise NewTreeException

                self.root = curr

            break

        while True:
            self.__record_node(curr)
            if not curr.subnodes:
                break
            curr = curr.subnodes[0]
            
    def print_tree(self):
        print(f"(root): {self.root.name}")
        print_tree_node(self.root)


def print_tree_node(node, level = 0):
    print(f"{' ' * level}|")
    print(f"{' ' * level}\-{node.name}")
    
    if not node.subnodes:
        return
    
    for n in node.subnodes:
        print_tree_node(n, level+1)

def gen_chain(prev, line):
    if not line.strip():
        return (prev, None)

    curr = Node(line.strip().split("+")[0])
    if prev:
        curr.add_subnode(prev)

    return (prev, curr)

def print_chain(root, level = 0):
    curr = root 
    while True:
        print(f"{'**' * level} {curr.name}")
        if not curr.subnodes:
            return

        curr = curr.subnodes[0]

def main():
    fn = "/Users/ye.zhang/tmp/io-trace.log"
    trees = []
    tree = Tree()
    curr = None
    printed = []
    with open(fn) as data:
        in_stack = False
        for line in data:
            if not in_stack and not line.strip():
               in_stack = True
               continue

            if in_stack:
                prev, curr = gen_chain(curr, line)
                if curr:
                    continue
                
                in_stack = False
                try:
                    if not prev:
                        continue
                    tree.merge_chain(prev)
                except NewTreeException:
                    if tree.root.name not in printed:
                        tree.print_tree()
                    printed.append(tree.root.name)
                    tree = Tree()

if __name__ == "__main__":
    main()
