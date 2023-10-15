
# 2023/10/15 

~~- [ ] Before worker process data info, it should use a tree to check if the corresponding block (valid addr) can be invalidated by the latter invalidated block (invalid addr). By doing so, we reduce the number of updates of summary hdr.~~ (No, this might lead us miss some version).
- [x] Async flush of inode for creation, How? By doing so, we enable the deletion of this inode without interacting with PM. 
- [x] Change Data Queue to Operation Queue for better semantics. 
- [x] Async for deallocation and Sync for allocation.

# 2023/10/13 -- 2023/10/14

- [x] Decouple Summary Hdr with Inode to prevent random accesses in fsync.
~~- [ ] Using free cores to flush different metadata concurrently?~~
- [ ] How to resolve slow sync?
  - [x] Per File Queue
  - [x] Reduced Metadata (Append)
  - [x] Decoupled inode and summary hdr using hybrid inode data root (IDR). IDR is flushed only when inode is flushed.

# Before

- [x] Decoupled Worker. Each asynchronous worker dedicates to flush one type metadata. Metadata is object-oriented built to enable easy management.
- [x] Async arch. 