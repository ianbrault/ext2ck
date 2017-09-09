#!/usr/bin/python3
# ext2ck.py
# analyze a file system summary and report on all discovered inconsistencies
# Ian Brault <ianbrault@ucla.edu>

import math
import sys


# usage message
usage = "usage: ext2ck.py filename"

# filesystem metadata, read in from CSV
n_blocks    = 0
block_size  = 0
n_groups    = 0
n_inodes    = 0
first_block = 0
first_inode = 0

# inodes that have been allocated but appear on the freelist
# necessary so that directory entries that point to such inodes
# are not incorrectly logged
alloc_but_on_freelist = []


def open_csv():
    """ 
    parse the command-line arguments for the CSV file
    if an invalid # of args are provided, exit
    otherwise, open the specified file, exiting if not found
    @return : a file object of the specified CSV file
    """

    if len(sys.argv) != 2:
        sys.stderr.write("error: invalid arguments\n{0}\n".format(usage))
        sys.exit(1)

    # open file
    try:
        csv_file = open(sys.argv[1], 'r')
        return csv_file
    except IOError as err:
        sys.stderr.write("I/O Error: {0}\n".format(err))
        sys.exit(1)


def block_consistency_audit(csv):
    """
    examine all inode block pointers (including all indirect blocks),
    reporting (to stdout) invalid/reserved blocks, unreferenced blocks, 
    allocated blocks on the free list, and blocks referenced by multiple files
    @param : the file object for the CSV file
    """

    # store all allocated, referenced blocks
    used_blocks = []
    free_blocks = []

    # used to recover all references to duplicate blocks
    # entries are in the form: (block #, level, inode, offset)
    dup_blocks = []

    # message skeletons, fill in with str.format()
    inval_msg = "INVALID {0} {1} IN INODE {2} AT OFFSET {3}\n"
    rsrvd_msg = "RESERVED {0} {1} IN INODE {2} AT OFFSET {3}\n"
    unref_msg = "UNREFERENCED BLOCK {0}\n"
    alloc_free_msg = "ALLOCATED BLOCK {0} ON FREELIST\n"
    dup_msg = "DUPLICATE {0} {1} IN INODE {2} AT OFFSET {3}\n"

    # reset offset into CSV file
    csv.seek(0)
    # read CSV line-by-line
    for line in csv:
        entries = line.rstrip('\n').split(',')
        
        # check each allocated block in inodes
        if entries[0] == 'INODE':
            inode_num = entries[1]
            b = 0

            # check direct blocks
            for block in entries[12:24]:
                # invalid block
                if int(block) > n_blocks:
                    sys.stdout.write(
                        inval_msg.format('BLOCK', block, inode_num, b)
                    )
                # reserved block
                elif int(block) > 0 and int(block) < first_block:
                    sys.stdout.write(
                        rsrvd_msg.format('BLOCK', block, inode_num, b)
                    )
                # otherwise, log block as used
                elif int(block) > 0:
                    used_blocks.append(int(block))
                    dup_blocks.append((int(block), 'BLOCK', inode_num, b))
                b += 1

            # check single, double, trip(p)le indirect blocks
            b = 1
            for block in entries[24:]:
                level = ''
                offset = 0
                if b == 1:
                    level = 'INDIRECT BLOCK'
                    offset = 12
                elif b == 2:
                    level = 'DOUBLE INDIRECT BLOCK'
                    offset = 268
                else:
                    level = 'TRIPPLE INDIRECT BLOCK'
                    offset = 65804
                
                # invalid block
                if int(block) > n_blocks:
                    sys.stdout.write(
                        inval_msg.format(level, block, inode_num, offset)
                    )
                # reserved block
                elif int(block) > 0 and int(block) < first_block:
                    sys.stdout.write(
                        rsrvd_msg.format(level, block, inode_num, offset)
                    )
                # otherwise, log block as used
                elif int(block) > 0:
                    used_blocks.append(int(block))
                    dup_blocks.append((int(block), level, inode_num, offset))
                b += 1

        # scan indirect blocks
        if entries[0] == 'INDIRECT':
            # inode number of owning file
            inode_num = entries[1]
            # logical block offset
            offset = entries[3]
            # block number of referenced block
            ref_block = int(entries[5])
            # level of indirection
            level = ''
            if entries[2] == '1':
                level = 'INDIRECT BLOCK'
            elif entries[2] == '2':
                level = 'DOUBLE INDIRECT BLOCK'
            else:
                level = 'TRIPPLE INDIRECT BLOCK'
                    
            # invalid block
            if ref_block > n_blocks:
                sys.stdout.write(
                    inval_msg.format(level, ref_block, inode_num, offset)
                )
            # reserved block
            elif ref_block > 0 and ref_block < first_block:
                sys.stdout.write(
                    rsrvd_msg.format(level, ref_block, inode_num, offset)
                )
            # otherwise, log block as used
            elif ref_block > 0:
                used_blocks.append(ref_block)
                dup_blocks.append((ref_block, level, inode_num, offset))

        # log free blocks
        if entries[0] == 'BFREE':
            free_blocks.append(int(entries[1]))

    # check for inconsistencies in...
    for i in range(first_block, n_blocks):
        # block not allocated & not on free list
        if i not in used_blocks and i not in free_blocks:
            sys.stdout.write(unref_msg.format(i))
        # block allocated but also on free list
        if i in used_blocks and i in free_blocks:
            sys.stdout.write(alloc_free_msg.format(i))

    # report all duplicate blocks
    for i in range(first_block, n_blocks):
        # get all allocated blocks with same #
        refs = [entry for entry in dup_blocks if entry[0] == i]
        if len(refs) > 1:
            for entry in refs:
                sys.stdout.write(
                    dup_msg.format(entry[1], entry[0], entry[2], entry[3])
                )


def inode_allocation_audit(csv):
    """
    ... fill in later ...
    """

    # store all allocated, referenced blocks
    freelist_inodes = []
    allocated_inodes = []
    
    # message skeletons, fill in with str.format()
    alloc_msg = "ALLOCATED INODE {0} ON FREELIST\n"
    unalloc_msg = "UNALLOCATED INODE {0} NOT ON FREELIST\n"
    
    # reset offset into CSV file
    csv.seek(0)
    # check each line
    for line in csv:
        entries = line.rstrip('\n').split(',')
        
        # check each allocated inode on freelist
        if entries[0] == 'IFREE':
            # add all inodes on freelist to list
            freelist_inodes.append(int(entries[1]))
            
        elif entries[0] == 'INODE':
            # add all allocated inodes to list
            allocated_inodes.append(int(entries[1]))

    for inode in freelist_inodes:
        # inode is on freelist but is allocated
        if inode in allocated_inodes:
            sys.stdout.write(alloc_msg.format(inode))
            global alloc_but_on_freelist
            alloc_but_on_freelist.append(inode)
        
    for j in range(first_inode, n_inodes):
        # there is an unallocated inode not on the freelist
        if j not in freelist_inodes and j not in allocated_inodes:
            sys.stdout.write(unalloc_msg.format(j))

            
def directory_consistency_audit(csv):
    """
    ... fill in later ...
    """
    
    # message skeletons, fill in with str.format()
    link_msg = "INODE {0} HAS {1} LINKS BUT LINKCOUNT IS {2}\n"
    unalloc_msg = "DIRECTORY INODE {0} NAME {1} UNALLOCATED INODE {2}\n"
    invalid_msg = "DIRECTORY INODE {0} NAME {1} INVALID INODE {2}\n"
    dot_msg  = "DIRECTORY INODE {0} NAME {1} LINK TO INODE {2} SHOULD BE {3}\n"
    
    inode_ref_count = {}
    inode_link_count = {}
    inode_freelist = []

    # stores info about the directory tree
    # entries are of the form { directory inode # : [list of subdirectories] }
    dir_tree = {}

    # initialize dicts
    # make sure to include root inode (always 2)
    inode_ref_count[2] = 0
    inode_link_count[2] = 0
    for i in range(first_inode, n_inodes):
        inode_ref_count[i] = 0
        inode_link_count[i] = 0
     
    # reset offset into CSV file
    csv.seek(0)
    for line in csv:
        entries = line.rstrip('\n').split(',')
        if entries[0] == 'IFREE':
            # log all inodes on the free list
            inode_freelist.append(int(entries[1]))
            
    # reset offset into CSV file
    csv.seek(0)
    # check each line
    for line in csv:
        entries = line.rstrip('\n').split(',')
        
        # update reference counts
        if entries[0] == 'DIRENT':
            inode_num  = int(entries[3])
            parent_num = int(entries[1])
            name = entries[6]

            valid = True

            # if inode number is invalid...
            if inode_num != 2 and inode_num < first_inode or inode_num > n_inodes:
                sys.stdout.write(
                    invalid_msg.format(parent_num, name, inode_num)
                )
                valid = False

            # if inode is in the free list...
            if inode_num in inode_freelist and inode_num not in alloc_but_on_freelist:
                sys.stdout.write(
                    unalloc_msg.format(parent_num, name, inode_num)
                )

            # if . doesn't reference itself...
            # NOTE: .. needs the full directory tree, needs a 2nd pass
            if name == "'.'" and inode_num != parent_num:
                sys.stdout.write(
                    dot_msg.format(parent_num, name, inode_num, parent_num)
                )

            # increase reference count, add to directory tree
            if valid:
                inode_ref_count[inode_num] += 1
                if name != "'..'":
                    dir_tree.setdefault(parent_num, []).append(inode_num)

        elif entries[0] == 'INODE':
            # update array with proper link counts
            inode_link_count[int(entries[1])] = int(entries[6])

    # check all .. entries
    csv.seek(0)
    for line in csv:
        entries = line.rstrip('\n').split(',')
        # if is a .. directory entry
        if entries[0] == 'DIRENT' and entries[6] == "'..'":
            this_dir = int(entries[1])
            parent = int(entries[3])
            
            # this directory should be a subdirectory of its parent
            if this_dir not in dir_tree.get(parent):
                # otherwise find the parent
                correct_parent = 0
                for key, value in dir_tree.items():
                    if this_dir in value:
                        correct_parent = key
                        break
                sys.stdout.write(
                    dot_msg.format(this_dir, "'..'", parent, correct_parent)
                )

    # make sure link count & reference count match up
    # first for root
    if inode_link_count[2] != inode_ref_count[2]:
        sys.stdout.write(
            link_msg.format(2, inode_ref_count[2], inode_link_count[2])
        )
    # then for others
    for i in range(first_inode, n_inodes):
        if i not in inode_freelist and inode_link_count[i] != inode_ref_count[i]:
            sys.stdout.write(
                link_msg.format(i, inode_ref_count[i], inode_link_count[i])
            )


def main():
    # declare globals
    global n_blocks
    global block_size
    global n_groups
    global n_inodes
    global first_inode
    global first_block
    global first_inode
    
    # parse command-line args & open csv file
    csv_file = open_csv()

    # read in superblock metadata
    superblock  = csv_file.readline().rstrip('\n').split(',')
    n_blocks    = int(superblock[1])
    block_size  = int(superblock[3])
    n_groups    = math.ceil(n_blocks / int(superblock[5]))
    n_inodes    = int(superblock[2])
    first_inode = int(superblock[7])

    # read in block group descriptor table
    bgdt = csv_file.readline().rstrip('\n').split(',')
    # first block is offset from BGDT 1st inode by:
    # (number of inodes * inode size / block size) blocks
    first_block = int(bgdt[8]) + math.ceil(
        (n_inodes * int(superblock[4])) / block_size)

    # find & report invalid blocks
    block_consistency_audit(csv_file)

    # find & report inconsistent free/allocated inodes
    inode_allocation_audit(csv_file)

    # find & report inconsistent directory entries/links
    directory_consistency_audit(csv_file)
    
    
if __name__ == '__main__':
    main()
