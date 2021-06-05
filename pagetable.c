#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>
#include <linux/sched/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Gryanko");
MODULE_DESCRIPTION("Shows pagetable for the process");
MODULE_VERSION("0.01");

/*
 * Mapping of Intel - Linux levels
 *
 * Level: L4          L3          L2        L1
 * Linux: PGD    -->  PDU    -->  PMD  -->  PTE
 * Intel: PML4E  -->  PDPTE  -->  PDE  -->  PTE
 *
 * Intel Vol. 3A 4-23
 *
 */

#define DEBUG_DIR "pagetable_dump"
#define MIN_PID 1000
#define MAX_PID_STR_LEN 13 // -2147483647 max string len is 11 plus '\n' symbol and '\0'
#define MAX_PT_ENTRIES 512

#define HUGE_2M_MASK 0xFFFFFFFE00000
#define HUGE_1G_MASK 0xFFFFFC0000000

#define ADDRESS_IDX_SHIFT 9
#define ADDRESS_OFFSET_SHIFT 12

#define L0_LINE        "|"
#define L1_LINE        "\\_____ "
#define L1_SPACE       "|       "
#define L1_SPACE_INNER "|           "
#define L2_LINE        "\\__________ "
#define L2_SPACE       "|           "
#define L2_SPACE_INNER "|               "
#define L3_LINE        "\\______________ "
#define L3_SPACE       "|                   "
#define L3_SPACE_INNER "|                       "
#define L4_LINE        "\\______________________ "
#define L4_SPACE       "|                       "
#define L4_SPACE_INNER "|                           "



static pid_t process_pid = 0;
static DEFINE_MUTEX(pagetable_lock);


struct raw_table {
	void* entry[MAX_PT_ENTRIES];
};

static ssize_t pid_read(struct file *filp, char *buf, size_t len, loff_t * offset) {
    char tmp[MAX_PID_STR_LEN];
    mutex_lock(&pagetable_lock);
    memset(&tmp, 0, MAX_PID_STR_LEN);
    sprintf(tmp, "%d\n", process_pid);
    mutex_unlock(&pagetable_lock);
    return simple_read_from_buffer(buf, len, offset, tmp, sizeof(tmp));
}

static ssize_t pid_write(struct file *filp, const char *buf, size_t len, loff_t * off) {
    // Read pid from userspace
    ssize_t ret = 0;
    mutex_lock(&pagetable_lock);
    ret = kstrtoint_from_user(buf, len, 0, &process_pid);
    if (ret) {
		ret = -EFAULT;
        goto err;
    }
	if (process_pid < 0) {
		ret = -EINVAL;
        goto err;
    }

    ret = len;
err:
    mutex_unlock(&pagetable_lock);
    return ret;
}

static struct file_operations pid_ops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = pid_read,
    .write = pid_write,
};

static void dump_pte(struct seq_file *m, u64 idx, u64 mask, void *table) {
    u64 entry = (u64)table;
    u64 phys = 0;
    u64 virt = 0;

    if(!(entry & _PAGE_PRESENT)) {
	    seq_printf(m, "%s PTE is not present\n", L4_SPACE);
        return;
    }

    seq_printf(m, "%s Page attrs:\n"
            "%s PAGE RW:       %s\n"
            "%s PAGE USER:     %s\n"
            "%s PAGE PWT:      %s\n"
            "%s PAGE PCD:      %s\n"
            "%s PAGE ACCESSED: %s\n"
            "%s PAGE NX:       %s\n"
            "%s PAGE DIRTY:    %s\n"
            "%s PAGE PAT:      %s\n"
            "%s PAGE GLOBAL:   %s\n",
                L4_SPACE,
                L4_SPACE_INNER,
			    entry & _PAGE_RW ? "Write" : "Read",
                L4_SPACE_INNER,
			    entry & _PAGE_USER ? "User" : "Kernel",
                L4_SPACE_INNER,
			    entry & _PAGE_PWT ? "True" : "False",
                L4_SPACE_INNER,
			    entry & _PAGE_PCD ? "True" : "False",
                L4_SPACE_INNER,
			    entry & _PAGE_ACCESSED ? "True" : "False",
                L4_SPACE_INNER,
			    entry & _PAGE_NX ? "True" : "False",
                L4_SPACE_INNER,
                entry & _PAGE_DIRTY ? "True" : "False",
                L4_SPACE_INNER,
                entry & _PAGE_PAT ? "True" : "False",
                L4_SPACE_INNER,
                entry & _PAGE_GLOBAL ? "True" : "False"
			);
    phys = entry & mask;
    seq_printf(m, "%s Page physical address 0x%llx\n", L4_SPACE, phys);
    virt = (u64)phys_to_virt(phys);
	if(!virt_addr_valid(virt) || !IS_ALIGNED(phys, PAGE_SIZE)){
        seq_printf(m, "%s Page has incorrect virtual address\n", L4_SPACE);
		return;
	}
    seq_printf(m, "%s Page kernel virtual address 0x%llx\n", L4_SPACE, virt);
    if (entry & _PAGE_USER) {
        seq_printf(m, "%s Page user virtual address 0x%llx\n", L4_SPACE, idx << ADDRESS_OFFSET_SHIFT);
    }

}

static void dump_pmd(struct seq_file *m, u64 idx, void *table) {
    struct raw_table *pte_tables = NULL;

    u64 entry = (u64)table;
    u64 pte_phys = 0;

    int pte_l1_i = 0;

    if(!(entry & _PAGE_PRESENT)) {
	    seq_printf(m, "%s PMD is not present\n", L3_SPACE);
        return;
    }

    if (entry & _PAGE_PSE) {
	    seq_printf(m, "%s PTE is 2MB HugePage\n", L3_SPACE);
        dump_pte(m, idx << (ADDRESS_IDX_SHIFT + ADDRESS_OFFSET_SHIFT), HUGE_2M_MASK, table);
        return;
    }

    seq_printf(m, "%s PMD attrs:\n"
            "%s PAGE RW:       %s\n"
            "%s PAGE USER:     %s\n"
            "%s PAGE PWT:      %s\n"
            "%s PAGE PCD:      %s\n"
            "%s PAGE ACCESSED: %s\n"
            "%s PAGE NX:       %s\n"
            "%sPAGE PSE:      %s\n",
                L3_SPACE,
                L3_SPACE_INNER,
			    entry & _PAGE_RW ? "Write" : "Read",
                L3_SPACE_INNER,
			    entry & _PAGE_USER ? "User" : "Kernel",
                L3_SPACE_INNER,
			    entry & _PAGE_PWT ? "True" : "False",
                L3_SPACE_INNER,
			    entry & _PAGE_PCD ? "True" : "False",
                L3_SPACE_INNER,
			    entry & _PAGE_ACCESSED ? "True" : "False",
                L3_SPACE_INNER,
			    entry & _PAGE_NX ? "True" : "False",
                L3_SPACE_INNER,
                entry & _PAGE_PSE ? "True" : "False" // HugePages 2M
			);

    pte_phys = entry & PHYSICAL_PAGE_MASK;
    seq_printf(m, "%s PTE entry physical address 0x%llx\n", L3_SPACE, pte_phys);
    pte_tables = phys_to_virt(pte_phys);
	if(!virt_addr_valid(pte_tables) || !IS_ALIGNED(pte_phys, PAGE_SIZE)){
        seq_printf(m, "%s PTE entry has incorrect virtual address\n", L3_SPACE);
		return;
	}
    seq_printf(m, "%s PTE entry virtual address 0x%llx\n", L3_SPACE, (u64)pte_tables);
    for (pte_l1_i = 0; pte_l1_i < MAX_PT_ENTRIES; ++pte_l1_i) {
        if (pte_tables->entry[pte_l1_i]) {
            seq_printf(m, "%s PTE idx %.3d persists in memory:\n", L4_LINE, pte_l1_i);
            dump_pte(m, pte_l1_i | (idx << ADDRESS_IDX_SHIFT), PHYSICAL_PAGE_MASK, pte_tables->entry[pte_l1_i]);
        }
    }
}

static void dump_pud(struct seq_file *m, u64 idx, void *table) {
    struct raw_table *pmd_tables = NULL;

    u64 entry = (u64)table;
    u64 pmd_phys = 0;

    int pmd_l2_i = 0;

    if(!(entry & _PAGE_PRESENT)) {
	    seq_printf(m, "%s PUD is not present\n", L2_SPACE);
        return;
    }

    if (entry & _PAGE_PSE) {
        // not tested
	    seq_printf(m, "%s PTE is 1GB HugePage\n", L3_SPACE);
        dump_pte(m, idx << (2 * ADDRESS_IDX_SHIFT + ADDRESS_OFFSET_SHIFT), HUGE_1G_MASK, table);
        return;
    }

    seq_printf(m, "%s PUD attrs:\n"
            "%s PAGE RW:       %s\n"
            "%s PAGE USER:     %s\n"
            "%s PAGE PWT:      %s\n"
            "%s PAGE PCD:      %s\n"
            "%s PAGE ACCESSED: %s\n"
            "%s PAGE NX:       %s\n"
            "%s PAGE PSE:      %s\n",
                L2_SPACE,
                L2_SPACE_INNER,
			    entry & _PAGE_RW ? "Write" : "Read",
                L2_SPACE_INNER,
			    entry & _PAGE_USER ? "User" : "Kernel",
                L2_SPACE_INNER,
			    entry & _PAGE_PWT ? "True" : "False",
                L2_SPACE_INNER,
			    entry & _PAGE_PCD ? "True" : "False",
                L2_SPACE_INNER,
			    entry & _PAGE_ACCESSED ? "True" : "False",
                L2_SPACE_INNER,
			    entry & _PAGE_NX ? "True" : "False",
                L2_SPACE_INNER,
                entry & _PAGE_PSE ? "True" : "False" // HugePages 1G
			);

    pmd_phys = entry & PHYSICAL_PAGE_MASK;
    seq_printf(m, "%s PMD entry physical address 0x%llx\n", L2_SPACE, pmd_phys);
    pmd_tables = phys_to_virt(pmd_phys);
	if(!virt_addr_valid(pmd_tables) || !IS_ALIGNED(pmd_phys, PAGE_SIZE)){
        seq_printf(m, "%s PMD entry has incorrect virtual address\n", L2_SPACE);
		return;
	}
    seq_printf(m, "%s PMD entry virtual address 0x%llx 0x%llx\n", L2_SPACE, (u64)pmd_tables, idx);
    for (pmd_l2_i = 0; pmd_l2_i < MAX_PT_ENTRIES; ++pmd_l2_i) {
        if (pmd_tables->entry[pmd_l2_i]) {
	        seq_printf(m, "%s PMD idx %.3d persists in memory:\n", L3_LINE, pmd_l2_i);
            dump_pmd(m, pmd_l2_i | (idx << ADDRESS_IDX_SHIFT), pmd_tables->entry[pmd_l2_i]);
        }
    }
   
}

static void dump_pgd(struct seq_file *m, u64 idx, void *table) {
    struct raw_table *pud_tables = NULL;

    u64 entry = (u64)table; // 4096 / 512 == 8 bytes or 64 bits per entry
    u64 pud_phys = 0;

    int pud_l3_i = 0;

	seq_printf(m, "%s PGD entry 0x%llx\n", L1_LINE, entry);
    if(!(entry & _PAGE_PRESENT)) {
	    seq_printf(m, "%s PGD is not present\n", L1_SPACE);
        return;
    }
    seq_printf(m, "%s PGD attrs:\n"
            "%s PAGE RW:       %s\n"
            "%s PAGE USER:     %s\n"
            "%s PAGE PWT:      %s\n"
            "%s PAGE PCD:      %s\n"
            "%s PAGE ACCESSED: %s\n"
            "%s PAGE NX:       %s\n"
            "%s PAGE PSE:      %s\n",
                L1_SPACE,
                L1_SPACE_INNER,
			    entry & _PAGE_RW ? "Write" : "Read",
                L1_SPACE_INNER,
			    entry & _PAGE_USER ? "User" : "Kernel",
                L1_SPACE_INNER,
			    entry & _PAGE_PWT ? "True" : "False",
                L1_SPACE_INNER,
			    entry & _PAGE_PCD ? "True" : "False",
                L1_SPACE_INNER,
			    entry & _PAGE_ACCESSED ? "True" : "False",
                L1_SPACE_INNER,
			    entry & _PAGE_NX ? "True" : "False",
                L1_SPACE_INNER,
                entry & _PAGE_PSE ? "True" : "False" // not possible for PGD
			);
    pud_phys = entry & PHYSICAL_PAGE_MASK;
    seq_printf(m, "%s PUD entry physical address 0x%llx\n", L1_SPACE, pud_phys);
    pud_tables = phys_to_virt(pud_phys);
	if(!virt_addr_valid(pud_tables) || !IS_ALIGNED(pud_phys, PAGE_SIZE)){
        seq_printf(m, "%s PUD entry has incorrect virtual address\n", L1_SPACE);
		return;
	}
    seq_printf(m, "%s PUD entry virtual address 0x%llx\n", L1_SPACE, (u64)pud_tables);
    for (pud_l3_i = 0; pud_l3_i < MAX_PT_ENTRIES; ++pud_l3_i) {
        if (pud_tables->entry[pud_l3_i]) {
	        seq_printf(m, "%s PUD idx %.3d persists in memory:\n", L2_LINE, pud_l3_i);
            dump_pud(m, pud_l3_i | (idx << ADDRESS_IDX_SHIFT), pud_tables->entry[pud_l3_i]);
        }
    }
}

static int dump_show(struct seq_file *m, void *p) {
    struct pid *pid_pt = NULL;
    struct task_struct *task_pt = NULL;
    struct mm_struct *mm_pt = NULL;
    struct raw_table *pgd_l4 = NULL;

    phys_addr_t pgd_phys;

    int pgd_l4_i = 0;

    if (process_pid < MIN_PID) {
		seq_printf(m, "pid %d is less than %d\n", process_pid, MIN_PID);
        goto exit;
    }

    pid_pt = find_get_pid(process_pid);
    if (!pid_pt) {
		seq_printf(m, "pid %d is not found\n", process_pid);
        goto exit;
    }

    task_pt = pid_task(pid_pt, PIDTYPE_PID);
    if (!task_pt) {
		seq_printf(m, "task with pid %d is not found\n", process_pid);
        goto exit;
    }

    mm_pt = get_task_mm(task_pt);
    if (!mm_pt) {
		seq_printf(m, "mm with pid %d is not found\n", process_pid);
        goto exit;
    }

    if (!mm_pt->pgd) {
		seq_printf(m, "PGD with pid %d is not found\n", process_pid);
        goto exit;
    }

    pgd_phys = virt_to_phys(mm_pt->pgd);
	seq_printf(m, "%s PGD virtual address is 0x%llx\n", L0_LINE, (u64)mm_pt->pgd);
	seq_printf(m, "%s PGD physical address is 0x%llx\n", L0_LINE, (u64)pgd_phys);

    // starting iteration through top-level directory
    pgd_l4 = (struct raw_table*)mm_pt->pgd;
    for (pgd_l4_i = 0; pgd_l4_i < MAX_PT_ENTRIES; ++pgd_l4_i) {
        if (pgd_l4->entry[pgd_l4_i]) {
	        seq_printf(m, "%s PGD idx %.3d persists in memory:\n", L0_LINE, pgd_l4_i);
            dump_pgd(m, pgd_l4_i, pgd_l4->entry[pgd_l4_i]);
        }
    }



exit:
	return 0;
}

static int dump_open(struct inode *inode, struct file *file) {
	return single_open(file, dump_show, inode->i_private);
}

static const struct file_operations dump_ops = {
	.owner		= THIS_MODULE,
	.open		= dump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct dentry *pagetable_dir;

static int __init pagetable_init(void) {
    BUILD_BUG_ON(PAGE_SIZE != 4096);
    BUILD_BUG_ON(PTRS_PER_PGD != MAX_PT_ENTRIES);
    BUILD_BUG_ON(PTRS_PER_PUD != MAX_PT_ENTRIES);
    BUILD_BUG_ON(PTRS_PER_PMD != MAX_PT_ENTRIES);
    BUILD_BUG_ON(PTRS_PER_PTE != MAX_PT_ENTRIES);

    pagetable_dir = debugfs_create_dir(DEBUG_DIR, NULL);

    if (!pagetable_dir) {
		return -ENOMEM;
    }

	if (!debugfs_create_file("pid", 0600, pagetable_dir, NULL, &pid_ops)) {
        goto err;
    }
	if (!debugfs_create_file("dump", 0400, pagetable_dir, NULL, &dump_ops)) {
        goto err;
    }

    return 0;
err:
    debugfs_remove_recursive(pagetable_dir);
    return -ENOMEM;
}

static void __exit pagetable_exit(void) {
    mutex_unlock(&pagetable_lock);
    debugfs_remove_recursive(pagetable_dir);
}

module_init(pagetable_init);
module_exit(pagetable_exit);
