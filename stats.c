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
	"create_inode_package",
	"create_data_package",
	"update_data_package",
	"create_unlink_package",
	"create_attr_package",
	"coarse_allocation",

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
	"free_blocks",
	"free_data_blocks",
	"free_log_blocks",
	"reserve_pkg",
	"reserve_pkg_in_layout",
	"tl_alloc_meta",
	"tl_alloc_blk",

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
	"imm_set_bitmap",
	"imm_clear_bitmap",

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

void hk_print_meta_stats(struct super_block *sb) {
	unsigned long meta_time = Timingstats[new_attr_trans_t] + Timingstats[new_data_trans_t]
		+ Timingstats[new_inode_trans_t] + Timingstats[new_unlink_trans_t]
		+ Timingstats[update_data_package_t] + Timingstats[imm_set_bm_t] + Timingstats[imm_clear_bm_t];
	
	unsigned long meta_times = 	Countstats[new_attr_trans_t] + Countstats[new_data_trans_t]
		+ Countstats[new_inode_trans_t] + Countstats[new_unlink_trans_t]
		+ Countstats[update_data_package_t] + Countstats[imm_set_bm_t] + Countstats[imm_clear_bm_t];

	pr_info("=========== KILLER meta_trace stats ============\n");
	pr_info("meta_read: %llu\n", IOstats[meta_read]);
	pr_info("meta_write: %llu\n", IOstats[meta_write]);
	pr_info("data_read: %llu\n", IOstats[file_read]);
	pr_info("data_write: %llu\n", IOstats[file_write]);
	pr_info("meta_time: %llu\n", meta_time);
	pr_info("meta_times: %llu", meta_times);
	pr_info("data_write_time: %llu\n", Timingstats[memcpy_w_nvmm_t]);
	pr_info("data_read_time: %llu\n", Timingstats[memcpy_r_nvmm_t]);
	pr_info("COW_time: %llu\n", Timingstats[write_t]);

	pr_info("mem_usage: %llu\n", IOstats[mem_usage]);
}

void hk_print_timing_stats(struct super_block *sb)
{
	int i;

	hk_get_timing_stats();
	hk_get_IO_stats();

	hk_info("=========== HUNTER kernel timing stats ===========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		/* Title */
		if (Timingstring[i][0] == '=') {
			hk_info("\n%s\n\n", Timingstring[i]);
			continue;
		}

		if (measure_timing || Timingstats[i]) {
			hk_info("%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			hk_info("%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}

	hk_info("\n");
	hk_print_meta_stats(sb);
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