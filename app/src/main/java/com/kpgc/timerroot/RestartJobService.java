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

    @Override
    public boolean onStartJob(JobParameters params) {
        AutoRoot.log(this, "restart job: starting auto-root");
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
