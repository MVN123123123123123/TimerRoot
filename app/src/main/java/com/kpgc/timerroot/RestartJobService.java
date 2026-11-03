package com.kpgc.timerroot;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

/**
 * Restarts AutoRootService in a fresh process.
 *
 * Shizuku's server can only push its binder to an app when the app's uid or
 * one of its pids changes state. At boot this app starts before the server,
 * so it never receives that push. Killing the process and letting the job
 * start it again gives the uid a gone -> active transition, which is the one
 * event the server does send the binder for.
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
