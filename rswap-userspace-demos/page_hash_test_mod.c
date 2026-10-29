// SPDX-License-Identifier: GPL-2.0-only
/*
 * page_hash_test_mod.c — Kernel module to test the page-hash BPF program
 *
 * == Overview ==
 *
 * This kernel module exercises the BPF program loaded and pinned by the
 * companion userspace program (page_hash_user).  It:
 *
 *   1. Reads the pinned BPF program path (module param or debugfs).
 *   2. Retrieves the BPF program via bpf_prog_get_type_path().
 *   3. Exposes a debugfs file so that userspace can write a page address
 *      and trigger an on-the-spot hash computation.
 *   4. Writes the computed SHA-256 (and a comparison with the user-supplied
 *      expected hash) to the kernel log.
 *
 * == Usage ==
 *
 *   # Load the module (the BPF program must already be pinned):
 *   insmod page_hash_test_mod.ko prog_path=/sys/fs/bpf/page_hash_prog
 *
 *   # Trigger a test from the process that owns the mmap'd region:
 *   echo <page-addr> [expected-hex-hash] > /sys/kernel/debug/page_hash_test/run
 *
 *   # Check kernel log for the result:
 *   dmesg | tail
 *
 * The write handler runs in the context of the calling process, so
 * bpf_probe_read_user() inside the BPF program sees the correct
 * task->mm and can read the page data.
 *
 * == Build ==
 *
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * or use the provided top-level Makefile.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/err.h>

/* ------------------------------------------------------------------ */
/*  Module parameters                                                  */
/* ------------------------------------------------------------------ */

static char *prog_path = "/sys/fs/bpf/page_hash_prog";
module_param(prog_path, charp, 0444);
MODULE_PARM_DESC(prog_path, "Path to the pinned BPF program in bpffs");

/* ------------------------------------------------------------------ */
/*  Per-page metadata (must match userspace & BPF program)             */
/* ------------------------------------------------------------------ */

#define SHA256_DIGEST_LEN  32

/* Context struct passed to the SEC("syscall") entry point.
 * Must be identical to struct get_hash_args in page_hash.h.
 */
/* Must be identical to struct get_hash_args in page_hash.h */
struct get_hash_args {
	unsigned long long  ptr;
	unsigned long long  page_size;  /* ignored by current BPF prog (hardcoded 4096) */
	unsigned char       hash[SHA256_DIGEST_LEN];
};

/* ------------------------------------------------------------------ */
/*  Debugfs                                                           */
/* ------------------------------------------------------------------ */

static struct dentry *debugfs_dir;
static struct dentry *debugfs_run;

/* BPF program reference (obtained on module init). */
static struct bpf_prog *test_prog;

/* ------------------------------------------------------------------ */
/*  Hex helpers                                                       */
/* ------------------------------------------------------------------ */

/* Parse a hex string into a byte array.  Returns number of bytes
 * written, or -EINVAL on error.
 */
static int hex_to_bytes(const char *hex, size_t hex_len,
			unsigned char *out, size_t out_max)
{
	size_t i, j;

	if (hex_len < 2 || hex_len % 2)
		return -EINVAL;

	for (i = 0, j = 0; i < hex_len && j < out_max; i += 2, j++) {
		char hi = hex[i];
		char lo = hex[i + 1];
		u8  nib;

		/* High nibble */
		if (hi >= '0' && hi <= '9')
			nib = (hi - '0') << 4;
		else if (hi >= 'a' && hi <= 'f')
			nib = (hi - 'a' + 10) << 4;
		else if (hi >= 'A' && hi <= 'F')
			nib = (hi - 'A' + 10) << 4;
		else
			return -EINVAL;

		/* Low nibble */
		if (lo >= '0' && lo <= '9')
			nib |= (lo - '0');
		else if (lo >= 'a' && lo <= 'f')
			nib |= (lo - 'a' + 10);
		else if (lo >= 'A' && lo <= 'F')
			nib |= (lo - 'A' + 10);
		else
			return -EINVAL;

		out[j] = nib;
	}
	return j;
}

/* Format 32 bytes as a hex string (no trailing newline). */
static void hex_string(const unsigned char *data, size_t len, char *out)
{
	static const char hex[] = "0123456789abcdef";

	for (size_t i = 0; i < len && i < 128; i++) {
		out[i * 2]     = hex[(data[i] >> 4) & 0xf];
		out[i * 2 + 1] = hex[data[i] & 0xf];
	}
	out[len * 2] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Run the BPF program and log the result                             */
/* ------------------------------------------------------------------ */

static int run_test(unsigned long addr,
		    const unsigned char *expected, size_t expected_len)
{
	struct get_hash_args args = { .ptr = addr };
	int ret;

	if (!test_prog) {
		pr_err("page_hash_test: no BPF program loaded\n");
		return -ENOENT;
	}

	/* Zero the output hash. */
	memset(&args.hash, 0, sizeof(args.hash));

	/* Run the BPF program (bpf_prog_run is a static inline). */
	ret = bpf_prog_run(test_prog, &args);

	/* Log the result. */
	{
		char hash_str[SHA256_DIGEST_LEN * 2 + 1];
		char exp_str[SHA256_DIGEST_LEN * 2 + 1];

		hex_string(args.hash, SHA256_DIGEST_LEN, hash_str);
		pr_info("page_hash_test: addr=%#lx  bpf_ret=%d  hash=%s\n",
			addr, ret, hash_str);

		if (expected && expected_len == SHA256_DIGEST_LEN) {
			hex_string(expected, SHA256_DIGEST_LEN, exp_str);
			if (memcmp(args.hash, expected, SHA256_DIGEST_LEN) == 0)
				pr_info("page_hash_test: >>> MATCH <<<  (expected=%s)\n",
					exp_str);
			else
				pr_info("page_hash_test: <<< MISMATCH >>>  expected=%s\n",
					exp_str);
		}
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Debugfs write handler                                              */
/* ------------------------------------------------------------------ */

/*
 * Write format (everything case-insensitive hex):
 *
 *   <page-address>                         — just compute & log
 *   <page-address> <expected-hex-hash>     — compute & compare
 *
 * Examples:
 *   echo 0x7f1234560000 > /sys/kernel/debug/page_hash_test/run
 *   echo 7f1234560000 abcd...0123 > /sys/kernel/debug/page_hash_test/run
 */
static ssize_t debugfs_run_write(struct file *file,
				 const char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	char buf[256];      /* 8 addr + 1 space + 64 hash + margin */
	unsigned long addr;
	unsigned char expected[SHA256_DIGEST_LEN];
	bool have_expected = false;
	char *p, *token;
	int ret;

	/* Copy the input string (bounded). */
	if (count >= sizeof(buf))
		return -E2BIG;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';

	/* Strip trailing newline. */
	p = buf + count - 1;
	while (p >= buf && (*p == '\n' || *p == '\r'))
		*p-- = '\0';

	/* Parse the first token: page address.
	 * Use simple_strtoul() which stops at any non-digit character,
	 * unlike kstrtoul() which fails if the entire string isn't consumed.
	 */
	token = buf;
	while (*token && isspace(*token))
		token++;
	if (!*token)
		return -EINVAL;

	addr = simple_strtoul(token, &p, 0);
	if (addr == 0 && p == token)
		return -EINVAL;

	/* Parse optional second token: expected SHA-256 hex hash.
	 * p already points past the address digits, skip whitespace.
	 */
	while (*p && isspace(*p))
		*p++ = '\0';

	if (*p) {
		/* Strip trailing whitespace. */
		char *end = p + strlen(p) - 1;
		while (end >= p && isspace(*end))
			*end-- = '\0';

		ret = hex_to_bytes(p, strlen(p), expected, SHA256_DIGEST_LEN);
		if (ret < 0) {
			pr_err("page_hash_test: bad expected hash format\n");
			return -EINVAL;
		}
		if (ret != SHA256_DIGEST_LEN) {
			pr_err("page_hash_test: expected hash must be %d hex chars\n",
			       SHA256_DIGEST_LEN * 2);
			return -EINVAL;
		}
		have_expected = true;
	}

	/* Run the test. */
	ret = run_test(addr, have_expected ? expected : NULL,
		       have_expected ? SHA256_DIGEST_LEN : 0);
	if (ret)
		return ret;

	return count;
}

/* File operations for the debugfs 'run' entry. */
static const struct file_operations debugfs_run_fops = {
	.write = debugfs_run_write,
};

/* ------------------------------------------------------------------ */
/*  Module init / exit                                                 */
/* ------------------------------------------------------------------ */

static int __init page_hash_test_init(void)
{
	int err = -ENODEV;

	pr_info("page_hash_test: loading (prog_path=%s)\n", prog_path);

	/* Get a reference to the pinned BPF program. */
	test_prog = bpf_prog_get_type_path(prog_path, BPF_PROG_TYPE_SYSCALL);
	if (IS_ERR(test_prog)) {
		err = PTR_ERR(test_prog);
		test_prog = NULL;
		pr_err("page_hash_test: cannot get BPF prog at '%s': %d\n",
		       prog_path, err);
		goto err_out;
	}
	pr_info("page_hash_test: got BPF prog (tag=%*phN)\n",
		(int)sizeof(test_prog->tag), test_prog->tag);

	/* Create debugfs directory and file. */
	debugfs_dir = debugfs_create_dir("page_hash_test", NULL);
	if (IS_ERR_OR_NULL(debugfs_dir)) {
		pr_err("page_hash_test: cannot create debugfs dir\n");
		err = -ENOMEM;
		goto err_put_prog;
	}

	debugfs_run = debugfs_create_file("run", 0200, debugfs_dir, NULL,
					  &debugfs_run_fops);
	if (IS_ERR_OR_NULL(debugfs_run)) {
		pr_err("page_hash_test: cannot create debugfs 'run' file\n");
		err = -ENOMEM;
		goto err_remove_dir;
	}

	pr_info("page_hash_test: ready — echo <addr> [expected_hash] > "
		"%s/run  to test\n", "/sys/kernel/debug/page_hash_test");
	return 0;

err_remove_dir:
	debugfs_remove_recursive(debugfs_dir);
err_put_prog:
	bpf_prog_put(test_prog);
	test_prog = NULL;
err_out:
	pr_err("page_hash_test: init failed (%d)\n", err);
	return err;
}

static void __exit page_hash_test_exit(void)
{
	pr_info("page_hash_test: unloading\n");

	debugfs_remove_recursive(debugfs_dir);

	if (test_prog) {
		bpf_prog_put(test_prog);
		test_prog = NULL;
	}

	pr_info("page_hash_test: unloaded\n");
}

module_init(page_hash_test_init);
module_exit(page_hash_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pi coding agent");
MODULE_DESCRIPTION("Kernel module to exercise the page-hash BPF program");
