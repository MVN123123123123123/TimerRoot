package com.kpgc.timerroot;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

/**
 * Restarts AutoRootService in a fresh process when the Shizuku binder never
 * arrived. shizuku_server pushes its binder to a uid that goes from gone to
 * active, so a fresh process start is a reliable way to ask for it again.
 *
 * This is only a fallback: with a direct-boot-aware provider the server's
 * normal start-up delivery reaches the app even while the user is locked.
 */
public class RestartJobService extends JobService {

    private static final int JOB_ID = 4211;
    /**
     * Watchdog job: re-armed while a long exploit stage runs, and left to fire
     * when the app process is killed under memory pressure. It covers the
     * window after the boot broadcast, where no further broadcast would
     * re-enter the service (jobs may be deferred until the unlock, which
     * BOOT_COMPLETED already handles).
     */
    private static final int WATCHDOG_JOB_ID = 4212;
    /** Fires this long after the last re-arm (i.e. after the last heartbeat). */
    private static final long WATCHDOG_DELAY_MS = 3 * 60 * 1000L;

    static void schedule(Context context) {
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler == null) {
            return;
        }
        JobInfo.Builder builder = new JobInfo.Builder(JOB_ID,
                new ComponentName(context, RestartJobService.class))
                .setMinimumLatency(1000)
                .setOverrideDeadline(4000);
        scheduler.schedule(builder.build());
    }

    /**
     * (Re-)arms the watchdog. Scheduling with the same id replaces the pending
     * job, so a live run keeps pushing it forward and it only fires once the
     * heartbeats stop.
     */
    static void scheduleWatchdog(Context context) {
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler == null) {
            return;
        }
        JobInfo.Builder builder = new JobInfo.Builder(WATCHDOG_JOB_ID,
                new ComponentName(context, RestartJobService.class))
                .setMinimumLatency(WATCHDOG_DELAY_MS)
                .setOverrideDeadline(WATCHDOG_DELAY_MS + 60_000L)
                /*
                 * A userspace restart (framework crash or the app's own soft
                 * restart) wipes non-persisted jobs without rebooting the
                 * kernel, which is exactly when the supervisor is dead and the
                 * detached plant is still running: the job is the only thing
                 * left that can bring the recovery back before the unlock.
                 */
                .setPersisted(true);
        scheduler.schedule(builder.build());
    }

    /** Drops the watchdog once the run has an outcome. */
    static void cancelWatchdog(Context context) {
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler != null) {
            scheduler.cancel(WATCHDOG_JOB_ID);
        }
    }

    @Override
    public boolean onStartJob(JobParameters params) {
        boolean watchdog = params.getJobId() == WATCHDOG_JOB_ID;
        AutoRoot.log(this, watchdog
                ? "watchdog job: the auto-root process is gone, restarting it"
                : "restart job: starting auto-root");
        try {
            startForegroundService(new Intent(this, AutoRootService.class)
                    .setAction(AutoRootService.ACTION_START));
        } catch (Throwable t) {
            AutoRoot.log(this, "restart job cannot start the service: " + t);
        }
        jobFinished(params, false);
        return false;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return false;
    }
}
