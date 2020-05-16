// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017-18 Intel Corporation.

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/threads.h>

#include "epc_cgroup.h"

#define SGX_EPC_RECLAIM_MIN_PAGES		16UL
#define SGX_EPC_RECLAIM_MAX_PAGES		64UL
#define SGX_EPC_RECLAIM_IGNORE_AGE_THRESHOLD	5
#define SGX_EPC_RECLAIM_OOM_THRESHOLD		5

struct sgx_epc_reclaim_control {
	struct sgx_epc_cgroup *epc_cg;
	int nr_fails;
	bool ignore_age;
};

static struct sgx_epc_cgroup *root_epc_cgroup __read_mostly;
static struct workqueue_struct *sgx_epc_cg_wq;

static int __init sgx_epc_cgroup_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_SGX))
		return 0;

	sgx_epc_cg_wq = alloc_workqueue("sgx_epc_cg_wq",
					WQ_UNBOUND | WQ_FREEZABLE,
					WQ_UNBOUND_MAX_ACTIVE);
	BUG_ON(!sgx_epc_cg_wq);

	return 0;
}
subsys_initcall(sgx_epc_cgroup_init);

static inline bool sgx_epc_cgroup_disabled(void)
{
	return !cgroup_subsys_enabled(sgx_epc_cgrp_subsys);
}

static
struct sgx_epc_cgroup *sgx_epc_cgroup_from_css(struct cgroup_subsys_state *css)
{
	return container_of(css, struct sgx_epc_cgroup, css);
}

static
struct sgx_epc_cgroup *sgx_epc_cgroup_from_task(struct task_struct *task)
{
	if (unlikely(!task))
		return NULL;
	return sgx_epc_cgroup_from_css(task_css(task, sgx_epc_cgrp_id));
}

static struct sgx_epc_cgroup *sgx_epc_cgroup_from_mm(struct mm_struct *mm)
{
	struct sgx_epc_cgroup *epc_cg;

	rcu_read_lock();
	do {
		epc_cg = sgx_epc_cgroup_from_task(rcu_dereference(mm->owner));
		if (unlikely(!epc_cg))
			epc_cg = root_epc_cgroup;
	} while (!css_tryget_online(&epc_cg->css));
	rcu_read_unlock();

	return epc_cg;
}

static struct sgx_epc_cgroup *parent_epc_cgroup(struct sgx_epc_cgroup *epc_cg)
{
	return sgx_epc_cgroup_from_css(epc_cg->css.parent);
}

static inline unsigned long sgx_epc_cgroup_cnt_read(struct sgx_epc_cgroup *epc_cg,
						    enum sgx_epc_cgroup_counter i)
{
	return atomic_long_read(&epc_cg->cnt[i]);
}

static inline void sgx_epc_cgroup_cnt_reset(struct sgx_epc_cgroup *epc_cg,
					    enum sgx_epc_cgroup_counter i)
{
	atomic_long_set(&epc_cg->cnt[i], 0);
}

static inline void sgx_epc_cgroup_cnt_add(struct sgx_epc_cgroup *epc_cg,
					  enum sgx_epc_cgroup_counter i,
					  unsigned long cnt)
{
	atomic_long_add(cnt, &epc_cg->cnt[i]);
}

static inline void sgx_epc_cgroup_event(struct sgx_epc_cgroup *epc_cg,
					enum sgx_epc_cgroup_counter i,
					unsigned long cnt)
{
	sgx_epc_cgroup_cnt_add(epc_cg, i, cnt);

	if (i == SGX_EPC_CGROUP_LOW || i == SGX_EPC_CGROUP_HIGH ||
	    i == SGX_EPC_CGROUP_MAX)
		cgroup_file_notify(&epc_cg->events_file);
}

static inline void sgx_epc_cgroup_cnt_sub(struct sgx_epc_cgroup *epc_cg,
					  enum sgx_epc_cgroup_counter i,
					  unsigned long cnt)
{
	atomic_long_sub(cnt, &epc_cg->cnt[i]);
}

/**
 * sgx_epc_cgroup_iter - iterate over the EPC cgroup hierarchy
 * @root:		hierarchy root
 * @prev:		previously returned epc_cg, NULL on first invocation
 * @reclaim_epoch:	epoch for shared reclaim walks, NULL for full walks
 *
 * Return: references to children of the hierarchy below @root, or
 * @root itself, or %NULL after a full round-trip.
 *
 * Caller must pass the return value in @prev on subsequent invocations
 * for reference counting, or use sgx_epc_cgroup_iter_break() to cancel
 * a hierarchy walk before the round-trip is complete.
 */
static struct sgx_epc_cgroup *sgx_epc_cgroup_iter(struct sgx_epc_cgroup *prev,
						  struct sgx_epc_cgroup *root,
						  unsigned long *reclaim_epoch)
{
	struct cgroup_subsys_state *css = NULL;
	struct sgx_epc_cgroup *epc_cg = NULL;
	struct sgx_epc_cgroup *pos = NULL;
	bool inc_epoch = false;

	if (sgx_epc_cgroup_disabled())
		return NULL;

	if (!root)
		root = root_epc_cgroup;

	if (prev && !reclaim_epoch)
		pos = prev;

	rcu_read_lock();

start:
	if (reclaim_epoch) {
		/*
		 * Abort the walk if a reclaimer working from the same root has
		 * started a new walk after this reclaimer has already scanned
		 * at least one cgroup.
		 */
		if (prev && *reclaim_epoch != root->epoch)
			goto out;

		while (1) {
			pos = READ_ONCE(root->reclaim_iter);
			if (!pos || css_tryget(&pos->css))
				break;

			/*
			 * The css is dying, clear the reclaim_iter immediately
			 * instead of waiting for ->css_released to be called.
			 * Busy waiting serves no purpose and attempting to wait
			 * for ->css_released may actually block it from being
			 * called.
			 */
			(void)cmpxchg(&root->reclaim_iter, pos, NULL);
		}
	}

	if (pos)
		css = &pos->css;

	while (!epc_cg) {
		css = css_next_descendant_pre(css, &root->css);
		if (!css) {
			/*
			 * Increment the epoch as we've reached the end of the
			 * tree and the next call to css_next_descendant_pre
			 * will restart at root.  Do not update root->epoch
			 * directly as we should only do so if we update the
			 * reclaim_iter, i.e. a different thread may win the
			 * race and update the epoch for us.
			 */
			inc_epoch = true;

			/*
			 * Reclaimers share the hierarchy walk, and a new one
			 * might jump in at the end of the hierarchy.  Restart
			 * at root so that  we don't return NULL on a thread's
			 * initial call.
			 */
			if (!prev)
				continue;
			break;
		}

		/*
		 * Verify the css and acquire a reference.  Don't take an
		 * extra reference to root as it's either the global root
		 * or is provided by the caller and so is guaranteed to be
		 * alive.  Keep walking if this css is dying.
		 */
		if (css != &root->css && !css_tryget(css))
			continue;

		epc_cg = sgx_epc_cgroup_from_css(css);
	}

	if (reclaim_epoch) {
		/*
		 * reclaim_iter could have already been updated by a competing
		 * thread; check that the value hasn't changed since we read
		 * it to avoid reclaiming from the same cgroup twice.  If the
		 * value did change, put all of our references and restart the
		 * entire process, for all intents and purposes we're making a
		 * new call.
		 */
		if (cmpxchg(&root->reclaim_iter, pos, epc_cg) != pos) {
			if (epc_cg && epc_cg != root)
				css_put(&epc_cg->css);
			if (pos)
				css_put(&pos->css);
			css = NULL;
			epc_cg = NULL;
			inc_epoch = false;
			goto start;
		}

		if (inc_epoch)
			root->epoch++;
		if (!prev)
			*reclaim_epoch = root->epoch;

		if (pos)
			css_put(&pos->css);
	}

out:
	rcu_read_unlock();
	if (prev && prev != root)
		css_put(&prev->css);

	return epc_cg;
}

/**
 * sgx_epc_cgroup_iter_break - abort a hierarchy walk prematurely
 * @prev:	last visited cgroup as returned by sgx_epc_cgroup_iter()
 * @root:	hierarchy root
 */
static void sgx_epc_cgroup_iter_break(struct sgx_epc_cgroup *prev,
				      struct sgx_epc_cgroup *root)
{
	if (!root)
		root = root_epc_cgroup;
	if (prev && prev != root)
		css_put(&prev->css);
}

/**
 * sgx_epc_cgroup_lru_empty - check if a cgroup tree has no pages on its lrus
 * @root:	root of the tree to check
 *
 * Return: %true if all cgroups under the specified root have empty LRU lists.
 * Used to avoid livelocks due to a cgroup having a non-zero charge count but
 * no pages on its LRUs, e.g. due to a dead enclave waiting to be released or
 * because all pages in the cgroup are unreclaimable.
 */
bool sgx_epc_cgroup_lru_empty(struct sgx_epc_cgroup *root)
{
	struct sgx_epc_cgroup *epc_cg;

	for (epc_cg = sgx_epc_cgroup_iter(NULL, root, NULL);
	     epc_cg;
	     epc_cg = sgx_epc_cgroup_iter(epc_cg, root, NULL)) {
		if (!list_empty(&epc_cg->lru.reclaimable)) {
			sgx_epc_cgroup_iter_break(epc_cg, root);
			return false;
		}
	}
	return true;
}

static inline bool __sgx_epc_cgroup_is_low(struct sgx_epc_cgroup *epc_cg)
{
	unsigned long cur = page_counter_read(&epc_cg->pc);

	return cur < epc_cg->pc.low &&
	       cur < epc_cg->high &&
	       cur < epc_cg->pc.max;
}

/**
 * sgx_epc_cgroup_is_low - check if EPC consumption is below the normal range
 * @epc_cg:	the EPC cgroup to check
 * @root:	the top ancestor of the sub-tree being checked
 *
 * Returns %true if EPC consumption of @epc_cg, and that of all
 * ancestors up to (but not including) @root, is below the normal range.
 *
 * @root is exclusive; it is never low when looked at directly and isn't
 * checked when traversing the hierarchy.
 *
 * Excluding @root enables using sgx_epc.low to prioritize EPC usage
 * between cgroups within a subtree of the hierarchy that is limited
 * by sgx_epc.high or sgx_epc.max.
 *
 * For example, given cgroup A with children B and C:
 *
 *    A
 *   / \
 *  B   C
 *
 * and
 *
 *  1. A/sgx_epc.current > A/sgx_epc.high
 *  2. A/B/sgx_epc.current < A/B/sgx_epc.low
 *  3. A/C/sgx_epc.current >= A/C/sgx_epc.low
 *
 * As 'A' is high, i.e. triggers reclaim from 'A', and 'B' is low, we
 * should reclaim from 'C' until 'A' is no longer high or until we can
 * no longer reclaim from 'C'.  If 'A', i.e. @root, isn't excluded by
 * when reclaming from 'A', then 'B' will not be considered low and we
 * will reclaim indiscriminately from both 'B' and 'C'.
 */
static bool sgx_epc_cgroup_is_low(struct sgx_epc_cgroup *epc_cg,
				  struct sgx_epc_cgroup *root)
{
	if (sgx_epc_cgroup_disabled())
		return false;

	if (!root)
		root = root_epc_cgroup;
	if (epc_cg == root)
		return false;

	for (; epc_cg != root; epc_cg = parent_epc_cgroup(epc_cg)) {
		if (!__sgx_epc_cgroup_is_low(epc_cg))
			return false;
	}

	return true;
}

/**
 * sgx_epc_cgroup_all_in_use_are_low - check if all cgroups in a tree are low
 * @root:	the root EPC cgroup of the hierarchy to check
 *
 * Returns true if all cgroups in a hierarchy are either low or
 * or do not have any pages on their LRU.
 */
static bool sgx_epc_cgroup_all_in_use_are_low(struct sgx_epc_cgroup *root)
{
	struct sgx_epc_cgroup *epc_cg;

	if (sgx_epc_cgroup_disabled())
		return false;

	for (epc_cg = sgx_epc_cgroup_iter(NULL, root, NULL);
	     epc_cg;
	     epc_cg = sgx_epc_cgroup_iter(epc_cg, root, NULL)) {
		if (!list_empty(&epc_cg->lru.reclaimable) &&
		    !__sgx_epc_cgroup_is_low(epc_cg)) {
			sgx_epc_cgroup_iter_break(epc_cg, root);
			return false;
		}
	}

	return true;
}

void sgx_epc_cgroup_isolate_pages(struct sgx_epc_cgroup *root,
				  int *nr_to_scan, struct list_head *dst)
{
        struct sgx_epc_cgroup *epc_cg;
        unsigned long epoch;
	bool do_high;

	if (!*nr_to_scan)
		return;

	/*
	 * If we're not targeting a specific cgroup, try to reclaim only from
	 * cgroups that are above their high limit.  If there are none, then go
	 * ahead and grab anything available.
	 */
	do_high = !root;
retry:
        for (epc_cg = sgx_epc_cgroup_iter(NULL, root, &epoch);
             epc_cg;
             epc_cg = sgx_epc_cgroup_iter(epc_cg, root, &epoch)) {
		if (do_high && page_counter_read(&epc_cg->pc) < epc_cg->high)
			continue;

                if (sgx_epc_cgroup_is_low(epc_cg, root)) {
                        /*
                         * Ignore low if all cgroups below @root are low,
			 * in which case low is "normal".
                         */
                        if (!sgx_epc_cgroup_all_in_use_are_low(root))
                                continue;
			sgx_epc_cgroup_event(epc_cg, SGX_EPC_CGROUP_LOW, 1);
                }
		sgx_epc_cgroup_event(epc_cg, SGX_EPC_CGROUP_RECLAMATIONS, 1);

                sgx_isolate_epc_pages(&epc_cg->lru, nr_to_scan, dst);
                if (!*nr_to_scan) {
                        sgx_epc_cgroup_iter_break(epc_cg, root);
                        break;
                }
        }
	if (*nr_to_scan && do_high) {
		do_high = false;
		goto retry;
	}
}

static int sgx_epc_cgroup_reclaim_pages(unsigned long nr_pages,
					struct sgx_epc_reclaim_control *rc,
					enum sgx_epc_cgroup_counter c)
{
	sgx_epc_cgroup_event(rc->epc_cg, c, 1);

	/*
	 * Ensure sgx_reclaim_pages is called with a minimum and maximum
	 * number of pages.  Attempting to reclaim only a few pages will
	 * often fail and is inefficient, while reclaiming a huge number
	 * of pages can result in soft lockups due to holding various
	 * locks for an extended duration.  This also bounds nr_pages so
	 * that its guaranteed not to overflow 'int nr_to_scan'.
	 */
	nr_pages = max(nr_pages, SGX_EPC_RECLAIM_MIN_PAGES);
	nr_pages = min(nr_pages, SGX_EPC_RECLAIM_MAX_PAGES);

	return sgx_reclaim_epc_pages(nr_pages, rc->ignore_age, rc->epc_cg);
}

static int sgx_epc_cgroup_reclaim_failed(struct sgx_epc_reclaim_control *rc)
{
	if (sgx_epc_cgroup_lru_empty(rc->epc_cg))
		return -ENOMEM;

	++rc->nr_fails;
	if (rc->nr_fails > SGX_EPC_RECLAIM_IGNORE_AGE_THRESHOLD)
		rc->ignore_age = true;

	return 0;
}

static inline
void sgx_epc_reclaim_control_init(struct sgx_epc_reclaim_control *rc,
				  struct sgx_epc_cgroup *epc_cg)
{
	rc->epc_cg = epc_cg;
	rc->nr_fails = 0;
	rc->ignore_age = false;
}

static inline void __sgx_epc_cgroup_reclaim_high(struct sgx_epc_cgroup *epc_cg)
{
	struct sgx_epc_reclaim_control rc;
	unsigned long cur, high;

	sgx_epc_reclaim_control_init(&rc, epc_cg);

	for (;;) {
		high = READ_ONCE(epc_cg->high);

		cur = page_counter_read(&epc_cg->pc);
		if (cur <= high)
			break;

		if (!sgx_epc_cgroup_reclaim_pages(cur - high, &rc,
						  SGX_EPC_CGROUP_HIGH)) {
			if (sgx_epc_cgroup_reclaim_failed(&rc))
				break;
		}
	}
}

static void sgx_epc_cgroup_reclaim_high(struct sgx_epc_cgroup *epc_cg)
{
	for (; epc_cg; epc_cg = parent_epc_cgroup(epc_cg))
		__sgx_epc_cgroup_reclaim_high(epc_cg);
}

/*
 * Scheduled by sgx_epc_cgroup_try_charge() to reclaim pages from the
 * cgroup, either when the cgroup is at/near its maximum capacity or
 * when the cgroup is above its high threshold.
 */
static void sgx_epc_cgroup_reclaim_work_func(struct work_struct *work)
{
	struct sgx_epc_reclaim_control rc;
	struct sgx_epc_cgroup *epc_cg;
	unsigned long cur, max;

	epc_cg = container_of(work, struct sgx_epc_cgroup, reclaim_work);

	sgx_epc_reclaim_control_init(&rc, epc_cg);

	for (;;) {
		max = READ_ONCE(epc_cg->pc.max);

		/*
		 * Adjust the limit down by one page, the goal is to free up
		 * pages for fault allocations, not to simply obey the limit.
		 * Conditionally decrementing max also means the cur vs. max
		 * check will correctly handle the case where both are zero.
		 */
		if (max)
			max--;

		/*
		 * Unless the limit is extremely low, in which case forcing
		 * reclaim will likely cause thrashing, force the cgroup to
		 * reclaim at least once if it's operating *near* its maximum
		 * limit by adjusting @max down by half the min reclaim size.
		 * This work func is scheduled by sgx_epc_cgroup_try_charge
		 * when it cannot directly reclaim due to being in an atomic
		 * context, e.g. EPC allocation in a fault handler.  Waiting
		 * to reclaim until the cgroup is actually at its limit is less
		 * performant as it means the faulting task is effectively
		 * blocked until a worker makes its way through the global work
		 * queue.
		 */
		if (max > SGX_EPC_RECLAIM_MAX_PAGES)
			max -= (SGX_EPC_RECLAIM_MIN_PAGES/2);

		cur = page_counter_read(&epc_cg->pc);
		if (cur <= max)
			break;

		if (!sgx_epc_cgroup_reclaim_pages(cur - max, &rc,
						  SGX_EPC_CGROUP_MAX)) {
			if (sgx_epc_cgroup_reclaim_failed(&rc))
				break;
		}
	}

	sgx_epc_cgroup_reclaim_high(epc_cg);
}

static int __sgx_epc_cgroup_try_charge(struct sgx_epc_cgroup *epc_cg,
				       unsigned long nr_pages, bool reclaim)
{
	struct sgx_epc_reclaim_control rc;
	unsigned long cur, max, over;
	unsigned int nr_empty = 0;
	struct page_counter *fail;

	if (epc_cg == root_epc_cgroup) {
		page_counter_charge(&epc_cg->pc, nr_pages);
		return 0;
	}

	sgx_epc_reclaim_control_init(&rc, NULL);

	for (;;) {
		if (page_counter_try_charge(&epc_cg->pc, nr_pages, &fail))
			break;

		rc.epc_cg = container_of(fail, struct sgx_epc_cgroup, pc);
		max = READ_ONCE(rc.epc_cg->pc.max);
		if (nr_pages > max)
			return -ENOMEM;

		if (signal_pending(current))
			return -ERESTARTSYS;

		if (!reclaim) {
			queue_work(sgx_epc_cg_wq, &rc.epc_cg->reclaim_work);
			return -EBUSY;
		}

		cur = page_counter_read(&rc.epc_cg->pc);
		over = ((cur + nr_pages) > max) ?
			(cur + nr_pages) - max : SGX_EPC_RECLAIM_MIN_PAGES;

		if (!sgx_epc_cgroup_reclaim_pages(over, &rc,
						  SGX_EPC_CGROUP_MAX)) {
			if (sgx_epc_cgroup_reclaim_failed(&rc)) {
				if (++nr_empty > SGX_EPC_RECLAIM_OOM_THRESHOLD)
					return -ENOMEM;
				schedule();
			}
		}
	}

	css_get_many(&epc_cg->css, nr_pages);

	for (; epc_cg; epc_cg = parent_epc_cgroup(epc_cg)) {
		if (page_counter_read(&epc_cg->pc) >= epc_cg->high) {
			if (!reclaim)
				queue_work(sgx_epc_cg_wq, &epc_cg->reclaim_work);
			else
				sgx_epc_cgroup_reclaim_high(epc_cg);
			break;
		}
	}
	return 0;
}


/**
 * sgx_epc_cgroup_try_charge - hierarchically try to charge a single EPC page
 * @mm:			the mm_struct of the process to charge
 * @reclaim:		whether or not synchronous reclaim is allowed
 * @epc_cg_ptr:		out parameter for the charged EPC cgroup
 *
 * Returns EPC cgroup or NULL on success, -errno on failure.
 */
struct sgx_epc_cgroup *sgx_epc_cgroup_try_charge(struct mm_struct *mm,
						 bool reclaim)
{
	struct sgx_epc_cgroup *epc_cg;
	int ret;

	if (sgx_epc_cgroup_disabled())
		return NULL;

	epc_cg = sgx_epc_cgroup_from_mm(mm);
	ret = __sgx_epc_cgroup_try_charge(epc_cg, 1, reclaim);
	css_put(&epc_cg->css);

	if (ret)
		return ERR_PTR(ret);

	sgx_epc_cgroup_cnt_add(epc_cg, SGX_EPC_CGROUP_PAGES, 1);
	return epc_cg;
}

/**
 * sgx_epc_cgroup_uncharge - hierarchically uncharge EPC pages
 * @epc_cg:	the charged epc cgroup
 * @nr_pages:	the number of pages to uncharge
 * @reclaimed:	whether the pages were reclaimed (vs. freed)
 */
void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg, bool reclaimed)
{
	if (sgx_epc_cgroup_disabled())
		return;

	page_counter_uncharge(&epc_cg->pc, 1);
	sgx_epc_cgroup_cnt_sub(epc_cg, SGX_EPC_CGROUP_PAGES, 1);
	if (reclaimed)
		sgx_epc_cgroup_event(epc_cg, SGX_EPC_CGROUP_RECLAIMED, 1);

	if (epc_cg != root_epc_cgroup)
		css_put_many(&epc_cg->css, 1);
}

static void sgx_epc_cgroup_oom(struct sgx_epc_cgroup *root)
{
	struct sgx_epc_cgroup *epc_cg;

	for (epc_cg = sgx_epc_cgroup_iter(NULL, root, NULL);
	     epc_cg;
	     epc_cg = sgx_epc_cgroup_iter(epc_cg, root, NULL)) {
		if (sgx_epc_oom(&epc_cg->lru)) {
			sgx_epc_cgroup_iter_break(epc_cg, root);
			return;
		}
	}
}

static struct cgroup_subsys_state *
sgx_epc_cgroup_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct sgx_epc_cgroup *parent = sgx_epc_cgroup_from_css(parent_css);
	struct sgx_epc_cgroup *epc_cg;

	epc_cg = kzalloc(sizeof(struct sgx_epc_cgroup), GFP_KERNEL);
	if (!epc_cg)
		return ERR_PTR(-ENOMEM);

	if (!parent)
		root_epc_cgroup = epc_cg;

	epc_cg->high = PAGE_COUNTER_MAX;
	sgx_lru_init(&epc_cg->lru);
	page_counter_init(&epc_cg->pc, parent ? &parent->pc : NULL);
	INIT_WORK(&epc_cg->reclaim_work, sgx_epc_cgroup_reclaim_work_func);

	return &epc_cg->css;
}

static void sgx_epc_cgroup_css_released(struct cgroup_subsys_state *css)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(css);
	struct sgx_epc_cgroup *dead_cg = epc_cg;

	while ((epc_cg = parent_epc_cgroup(epc_cg)))
		cmpxchg(&epc_cg->reclaim_iter, dead_cg, NULL);
}

static void sgx_epc_cgroup_css_free(struct cgroup_subsys_state *css)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(css);

	cancel_work_sync(&epc_cg->reclaim_work);
	kfree(epc_cg);
}

static u64 sgx_epc_current_read(struct cgroup_subsys_state *css,
				struct cftype *cft)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(css);

	return (u64)page_counter_read(&epc_cg->pc) * PAGE_SIZE;
}

static int sgx_epc_stats_show(struct seq_file *m, void *v)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(seq_css(m));

	unsigned long cur, dir, rec, recs;
	cur = page_counter_read(&epc_cg->pc);
	dir = sgx_epc_cgroup_cnt_read(epc_cg, SGX_EPC_CGROUP_PAGES);
	rec = sgx_epc_cgroup_cnt_read(epc_cg, SGX_EPC_CGROUP_RECLAIMED);
	recs= sgx_epc_cgroup_cnt_read(epc_cg, SGX_EPC_CGROUP_RECLAMATIONS);

	seq_printf(m, "pages            %lu\n", cur);
	seq_printf(m, "direct           %lu\n", dir);
	seq_printf(m, "indirect         %lu\n", (cur - dir));
	seq_printf(m, "reclaimed        %lu\n", rec);
	seq_printf(m, "reclamations	%lu\n", recs);

	return 0;
}

static ssize_t sgx_epc_stats_reset(struct kernfs_open_file *of,
				   char *buf, size_t nbytes, loff_t off)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(of_css(of));
	sgx_epc_cgroup_cnt_reset(epc_cg, SGX_EPC_CGROUP_RECLAIMED);
	sgx_epc_cgroup_cnt_reset(epc_cg, SGX_EPC_CGROUP_RECLAMATIONS);
	return nbytes;
}


static int sgx_epc_events_show(struct seq_file *m, void *v)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(seq_css(m));

	unsigned long low, high, max;
	low  = sgx_epc_cgroup_cnt_read(epc_cg, SGX_EPC_CGROUP_LOW);
	high = sgx_epc_cgroup_cnt_read(epc_cg, SGX_EPC_CGROUP_HIGH);
	max  = sgx_epc_cgroup_cnt_read(epc_cg, SGX_EPC_CGROUP_MAX);

	seq_printf(m, "low      %lu\n", low);
	seq_printf(m, "high     %lu\n", high);
	seq_printf(m, "max      %lu\n", max);

	return 0;
}

static ssize_t sgx_epc_events_reset(struct kernfs_open_file *of,
				    char *buf, size_t nbytes, loff_t off)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(of_css(of));
	sgx_epc_cgroup_cnt_reset(epc_cg, SGX_EPC_CGROUP_LOW);
	sgx_epc_cgroup_cnt_reset(epc_cg, SGX_EPC_CGROUP_HIGH);
	sgx_epc_cgroup_cnt_reset(epc_cg, SGX_EPC_CGROUP_MAX);
	return nbytes;
}

static int sgx_epc_low_show(struct seq_file *m, void *v)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(seq_css(m));
	unsigned long low = READ_ONCE(epc_cg->pc.low);

	if (low == PAGE_COUNTER_MAX)
		seq_puts(m, "max\n");
	else
		seq_printf(m, "%llu\n", (u64)low * PAGE_SIZE);

	return 0;
}

static ssize_t sgx_epc_low_write(struct kernfs_open_file *of,
				 char *buf, size_t nbytes, loff_t off)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(of_css(of));
	unsigned long low;
	int err;

	buf = strstrip(buf);
	err = page_counter_memparse(buf, "max", &low);
	if (err)
		return err;

	page_counter_set_low(&epc_cg->pc, low);

	return nbytes;
}

static int sgx_epc_high_show(struct seq_file *m, void *v)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(seq_css(m));
	unsigned long high = READ_ONCE(epc_cg->high);

	if (high == PAGE_COUNTER_MAX)
		seq_puts(m, "max\n");
	else
		seq_printf(m, "%llu\n", (u64)high * PAGE_SIZE);

	return 0;
}

static ssize_t sgx_epc_high_write(struct kernfs_open_file *of,
				  char *buf, size_t nbytes, loff_t off)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(of_css(of));
	struct sgx_epc_reclaim_control rc;
	unsigned long cur, high;
	int err;

	buf = strstrip(buf);
	err = page_counter_memparse(buf, "max", &high);
	if (err)
		return err;

	epc_cg->high = high;

	sgx_epc_reclaim_control_init(&rc, epc_cg);

	for (;;) {
		cur = page_counter_read(&epc_cg->pc);
		if (cur <= high)
			break;

		if (signal_pending(current))
			break;

		if (!sgx_epc_cgroup_reclaim_pages(cur - high, &rc,
						  SGX_EPC_CGROUP_HIGH)) {
			if (sgx_epc_cgroup_reclaim_failed(&rc))
				break;
		}
	}

	return nbytes;
}

static int sgx_epc_max_show(struct seq_file *m, void *v)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(seq_css(m));
	unsigned long max = READ_ONCE(epc_cg->pc.max);

	if (max == PAGE_COUNTER_MAX)
		seq_puts(m, "max\n");
	else
		seq_printf(m, "%llu\n", (u64)max * PAGE_SIZE);

	return 0;
}


static ssize_t sgx_epc_max_write(struct kernfs_open_file *of, char *buf,
				 size_t nbytes, loff_t off)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(of_css(of));
	struct sgx_epc_reclaim_control rc;
	unsigned int nr_empty = 0;
	unsigned long cur, max;
	int err;

	buf = strstrip(buf);
	err = page_counter_memparse(buf, "max", &max);
	if (err)
		return err;

	xchg(&epc_cg->pc.max, max);

	sgx_epc_reclaim_control_init(&rc, epc_cg);

	for (;;) {
		cur = page_counter_read(&epc_cg->pc);
		if (cur <= max)
			break;

		if (signal_pending(current))
			break;

		if (!sgx_epc_cgroup_reclaim_pages(cur - max, &rc,
						  SGX_EPC_CGROUP_MAX)) {
			if (sgx_epc_cgroup_reclaim_failed(&rc)) {
				if (++nr_empty > SGX_EPC_RECLAIM_OOM_THRESHOLD)
					sgx_epc_cgroup_oom(epc_cg);
				schedule();
			}
		}
	}

	return nbytes;
}

static struct cftype sgx_epc_cgroup_files[] = {
	{
		.name = "current",
		.read_u64 = sgx_epc_current_read,
	},
	{
		.name = "stats",
		.seq_show = sgx_epc_stats_show,
		.write = sgx_epc_stats_reset,
	},
	{
		.name = "events",
		.flags = CFTYPE_NOT_ON_ROOT,
		.file_offset = offsetof(struct sgx_epc_cgroup, events_file),
		.seq_show = sgx_epc_events_show,
		.write = sgx_epc_events_reset,
	},
	{
		.name = "low",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = sgx_epc_low_show,
		.write = sgx_epc_low_write,
	},
	{
		.name = "high",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = sgx_epc_high_show,
		.write = sgx_epc_high_write,
	},
	{
		.name = "max",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = sgx_epc_max_show,
		.write = sgx_epc_max_write,
	},
	{ }	/* terminate */
};

struct cgroup_subsys sgx_epc_cgrp_subsys = {
	.css_alloc	= sgx_epc_cgroup_css_alloc,
	.css_free	= sgx_epc_cgroup_css_free,
	.css_released	= sgx_epc_cgroup_css_released,

	.legacy_cftypes	= sgx_epc_cgroup_files,
	.dfl_cftypes	= sgx_epc_cgroup_files,
};
