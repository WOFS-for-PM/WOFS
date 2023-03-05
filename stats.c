#include "hunter.h"

const char *Timingstring[TIMING_NUM] = {
	/* Init */
	"================ Initialization ================",
	"init",
	"mount",
	"ioremap",
	"new_init",
	"recovery",

	/* Namei operations */
	"============= Directory operations =============",
	"create",
	"lookup",
	"link",
	"unlink",
	"symlink",
	"mkdir",
	"rmdir",
	"mknod",
	"rename",
	"readdir",
	"add_dentry",
	"remove_dentry",
	"setattr",
	"setsize",

	/* I/O operations */
	"================ I/O operations ================",
	"dax_read",
	"do_cow_write",
	"cow_write",
	"copy_to_nvmm",
	"dax_get_block",
	"read_iter",
	"write_iter",
	"wrap_iter",
	"write",

	/* Memory operations */
	"============== Memory operations ===============",
	"memcpy_read_nvmm",
	"memcpy_write_nvmm",
	"memcpy_write_back_to_nvmm",
	"handle_partial_block",

	/* Memory management */
	"============== Memory management ===============",
	"alloc_blocks",
	"new_data_blocks",
	"new_log_blocks",
	"free_blocks",
	"free_data_blocks",
	"free_log_blocks",
	"reserve_pkg",
	"reserve_pkg_in_layout",

	/* Transaction */
	"================= Transaction ==================",
	"transaction_new_inode",
	"transaction_new_data",
	"transaction_new_unlink",
	"transaction_new_attr",
	"transaction_new_rename",
	"transaction_new_link",
	"transaction_new_symlink",
	"write_once_commit",

	/* Others */
	"================ Miscellaneous =================",
	"fsync",
	"write_pages",
	"fallocate",
	"direct_IO",
	"free_old_entry",
	"delete_file_tree",
	"delete_dir_tree",
	"new_vfs_inode",
	"new_hk_inode",
	"free_inode",
	"free_inode_log",
	"evict_inode",
	"test_perf",
	"wprotect",
	"bitmap_find_free",
	"process_reclaim_request",
	"data_claim",

	/* Mmap */
	"=============== MMap operations ================",
	"mmap_page_fault",
	"mmap_pmd_fault",
	"mmap_pfn_mkwrite",
	"insert_vma",
	"remove_vma",
	"set_vma_readonly",
	"mmap_cow",
	"udpate_mapping",
	"udpate_pfn",
	"mmap_handler",

	/* Rebuild */
	"=================== Rebuild ====================",
	"rebuild_dir",
	"rebuild_file",

	/* Meta Operations */
	"=================== Meta ===================", 
	"valid_summary_header",
	"invalid_summary_header",
	"request_valid_block",
	"request_invalid_block",
	"prepare_request",
	"commit_newattr",

	"=================== LinIX ===================",
	"linix_set",
	"linix_get"
};

u64 Timingstats[TIMING_NUM];
DEFINE_PER_CPU(u64[TIMING_NUM], Timingstats_percpu);
u64 Countstats[TIMING_NUM];
DEFINE_PER_CPU(u64[TIMING_NUM], Countstats_percpu);
u64 IOstats[STATS_NUM];
DEFINE_PER_CPU(u64[STATS_NUM], IOstats_percpu);

void hk_get_timing_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < TIMING_NUM; i++) {
		Timingstats[i] = 0;
		Countstats[i] = 0;
		for_each_possible_cpu(cpu) {
			Timingstats[i] += per_cpu(Timingstats_percpu[i], cpu);
			Countstats[i] += per_cpu(Countstats_percpu[i], cpu);
		}
	}
}


void hk_get_IO_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < STATS_NUM; i++) {
		IOstats[i] = 0;
		for_each_possible_cpu(cpu)
			IOstats[i] += per_cpu(IOstats_percpu[i], cpu);
	}
}

static void hk_clear_timing_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < TIMING_NUM; i++) {
		Countstats[i] = 0;
		Timingstats[i] = 0;
		for_each_possible_cpu(cpu) {
			per_cpu(Timingstats_percpu[i], cpu) = 0;
			per_cpu(Countstats_percpu[i], cpu) = 0;
		}
	}
}

static void hk_clear_IO_stats(struct super_block *sb)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	int i;
	int cpu;

	for (i = 0; i < STATS_NUM; i++) {
		IOstats[i] = 0;
		for_each_possible_cpu(cpu)
			per_cpu(IOstats_percpu[i], cpu) = 0;
	}
}

void hk_clear_stats(struct super_block *sb)
{
	hk_clear_timing_stats();
	hk_clear_IO_stats(sb);
}