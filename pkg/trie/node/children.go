// Copyright 2021 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package node

const (
	// ChildrenCapacity is the maximum number of children in a branch node.
	ChildrenCapacity = 16
)

// ChildrenBitmap returns the 16 bit bitmap
// of the children in the branch node.
func (n *Node) ChildrenBitmap() (bitmap uint16) {
	for i := range n.Children {
		if n.Children[i] == nil {
			continue
		}
		bitmap |= 1 << uint(i) //nolint:gosec
	}
	return bitmap
}

// NumChildren returns the total number of children
// in the branch node.
func (n *Node) NumChildren() (count int) {
	for i := range n.Children {
		if n.Children[i] != nil {
			count++
		}
	}
	return count
}

// HasChild returns true if the node has at least one child.
func (n *Node) HasChild() (has bool) {
	for _, child := range n.Children {
		if child != nil {
			return true
		}
	}
	return false
}
