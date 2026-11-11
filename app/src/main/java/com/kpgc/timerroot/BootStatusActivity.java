package com.kpgc.timerroot;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.os.UserManager;
import android.provider.Settings;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsets;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.VideoView;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Full-screen auto-root status, designed to be shown over the lock screen
 * before the first unlock (BFU).
 *
 * Direct boot keeps the APK's resources and device-protected storage
 * readable, so the activity can render while the credential-encrypted user
 * is still locked. It must never touch {@code getFilesDir()} of the normal
 * context; everything here goes through {@link AutoRoot#bootUiDir}.
 *
 * The screen is a normal activity with showWhenLocked/turnScreenOn. Android
 * launches it either through a full-screen-intent notification (the
 * sanctioned path; needs the "full-screen notifications" special access on
 * Android 14+) or directly when "Display over other apps" is granted.
 * Without either permission the foreground notification remains the
 * fallback.
 */
public class BootStatusActivity extends Activity {

    private static final String VIDEO_NAME = "background.video";
    private static final String IMAGE_PREFIX = "background.image";
    private static final long POLL_MS = 500;
    private static final long DONE_DELAY_MS = 6000;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final long created = System.currentTimeMillis();

    private Ring ring;
    private TextView title;
    private TextView subtitle;
    private TextView detail;
    private TextView hint;
    private View hideButton;
    private TextView turnOffButton;
    private Backdrop backdrop;
    private VideoView video;
    private ImageView image;
    private List<File> slides = new ArrayList<>();
    private int slideIndex;
    private Bitmap slideBitmap;
    private boolean userUnlocked;
    private boolean finishScheduled;
    private String lastText = "";
    private int lastState = Integer.MIN_VALUE;

    /** Cheap check for the direct-start BAL exemption. */
    static boolean canStartDirectly(Context context) {
        try {
            return Settings.canDrawOverlays(context);
        } catch (Throwable t) {
            return false;
        }
    }

    static Intent intent(Context context) {
        return new Intent(context, BootStatusActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                        | Intent.FLAG_ACTIVITY_CLEAR_TOP
                        | Intent.FLAG_ACTIVITY_SINGLE_TOP);
    }

    static PendingIntent pendingIntent(Context context) {
        return PendingIntent.getActivity(context, 3, intent(context),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    /**
     * Brings the status screen to the front if the user enabled it.
     *
     * At BFU the activity launch is a background activity launch, so it only
     * succeeds with the overlay exemption; otherwise the notification's
     * full-screen intent (attached in AutoRootService) launches it. Failures
     * are harmless and logged.
     */
    static void maybeShow(Context context) {
        if (!AutoRoot.bootUiWanted(context)) {
            return;
        }
        if (!canStartDirectly(context)) {
            return;
        }
        try {
            context.startActivity(intent(context));
        } catch (Throwable t) {
            AutoRoot.log(context, "boot UI start failed: " + t);
        }
    }

    private final Runnable poll = new Runnable() {
        @Override
        public void run() {
            update();
            ui.postDelayed(this, POLL_MS);
        }
    };

    private final BroadcastReceiver userPresent = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            userUnlocked = true;
            update();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setShowWhenLocked(true);
        setTurnScreenOn(true);

        userUnlocked = isUserUnlocked();
        buildUi();
        /*
         * getInsetsController() reaches through the DecorView, so it only
         * works once setContentView() (inside buildUi) has created it. On
         * Android 16 the controller is null before that and throws.
         */
        hideSystemBars();
        update();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (backdrop != null) {
            backdrop.setRunning(true);
        }
        if (ring != null) {
            ring.setRunning(true);
        }
        if (video != null) {
            video.start();
        }
        try {
            registerReceiver(userPresent, new IntentFilter(Intent.ACTION_USER_PRESENT));
        } catch (Throwable ignored) {
        }
        ui.removeCallbacks(poll);
        ui.post(poll);
        ui.removeCallbacks(slide);
        if (slides.size() > 1) {
            ui.postDelayed(slide, 9000);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(poll);
        ui.removeCallbacks(slide);
        if (backdrop != null) {
            backdrop.setRunning(false);
        }
        if (ring != null) {
            ring.setRunning(false);
        }
        if (video != null) {
            video.pause();
        }
        try {
            unregisterReceiver(userPresent);
        } catch (Throwable ignored) {
        }
    }

    @Override
    protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        if (video != null) {
            try {
                video.stopPlayback();
            } catch (Throwable ignored) {
            }
        }
        if (slideBitmap != null) {
            slideBitmap.recycle();
            slideBitmap = null;
        }
        super.onDestroy();
    }

    // ------------------------------------------------------------------ UI

    private void hideSystemBars() {
        Window window = getWindow();
        window.setStatusBarColor(0xFF000000);
        window.setNavigationBarColor(0xFF000000);
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(false);
            android.view.WindowInsetsController controller =
                    window.getInsetsController();
            if (controller != null) {
                controller.hide(WindowInsets.Type.systemBars());
                controller.setSystemBarsBehavior(
                        android.view.WindowInsetsController
                                .BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
            }
        }
    }

    private void buildUi() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(0xFF000000);

        File dir = AutoRoot.bootUiDir(this);
        File videoFile = new File(dir, VIDEO_NAME);
        List<File> images = imageFiles(dir);

        if (videoFile.isFile()) {
            backdrop = new Backdrop(this);
            root.addView(backdrop, match());
            attachVideo(root, videoFile);
        } else if (!images.isEmpty()) {
            backdrop = new Backdrop(this);
            root.addView(backdrop, match());
            slides = images;
            image = new ImageView(this);
            image.setScaleType(ImageView.ScaleType.CENTER_CROP);
            root.addView(image, match());
            showSlide(0);
        } else {
            backdrop = new Backdrop(this);
            root.addView(backdrop, match());
        }

        View scrim = new Scrim(this);
        root.addView(scrim, match());

        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setGravity(Gravity.CENTER_HORIZONTAL);
        panel.setPadding(dp(24), dp(22), dp(24), dp(26));
        GradientDrawable panelBg = new GradientDrawable();
        panelBg.setColor(0xB3000000);
        panelBg.setCornerRadius(dp(28));
        panel.setBackground(panelBg);

        ring = new Ring(this);
        LinearLayout.LayoutParams ringParams =
                new LinearLayout.LayoutParams(dp(88), dp(88));
        ringParams.bottomMargin = dp(14);
        panel.addView(ring, ringParams);

        title = text("TimerRoot", 30, Typeface.BOLD, 0xFFFFFFFF);
        title.setGravity(Gravity.CENTER);
        panel.addView(title);

        subtitle = text("waiting for the boot…", 16, Typeface.NORMAL, 0xFFD6E6EC);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, dp(6), 0, 0);
        panel.addView(subtitle);

        detail = text("", 13, Typeface.NORMAL, 0xFF8FA6AE);
        detail.setGravity(Gravity.CENTER);
        detail.setPadding(0, dp(8), 0, 0);
        panel.addView(detail);

        hint = text("", 12, Typeface.NORMAL, 0xFF6F858D);
        hint.setGravity(Gravity.CENTER);
        hint.setPadding(0, dp(12), 0, 0);
        panel.addView(hint);

        FrameLayout.LayoutParams panelParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        panelParams.leftMargin = dp(16);
        panelParams.rightMargin = dp(16);
        panelParams.bottomMargin = dp(36);
        root.addView(panel, panelParams);

        LinearLayout topBar = new LinearLayout(this);
        topBar.setOrientation(LinearLayout.HORIZONTAL);
        topBar.setGravity(Gravity.CENTER_VERTICAL);

        turnOffButton = button("Turn off", v -> turnOff());
        turnOffButton.setTextColor(0xFFFFB4A9);
        LinearLayout.LayoutParams turnOffParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        turnOffParams.rightMargin = dp(8);
        topBar.addView(turnOffButton, turnOffParams);

        hideButton = button("Hide", v -> hide());
        topBar.addView(hideButton);

        FrameLayout.LayoutParams topParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP | Gravity.END);
        topParams.topMargin = dp(18);
        topParams.rightMargin = dp(18);
        root.addView(topBar, topParams);

        setContentView(root);
    }

    private void attachVideo(FrameLayout root, File file) {
        video = new VideoView(this);
        /*
         * Keep the SurfaceView visible from the start. An INVISIBLE
         * SurfaceView has no surface yet, and VideoView only opens the
         * MediaPlayer once its surface exists, so the video would never
         * prepare. The Backdrop behind it is visible again if playback
         * fails.
         */
        video.setVisibility(View.VISIBLE);
        root.addView(video, match());
        video.setOnPreparedListener(mp -> {
            mp.setLooping(true);
            mp.setVolume(0f, 0f);
            cropVideo(mp.getVideoWidth(), mp.getVideoHeight());
            if (!isFinishing()) {
                video.start();
            }
        });
        video.setOnErrorListener((mp, what, extra) -> {
            AutoRoot.log(this, "boot UI video failed: " + what + "/" + extra);
            video.setVisibility(View.GONE);
            return true;
        });
        try {
            video.setVideoPath(file.getAbsolutePath());
            video.requestFocus();
        } catch (Throwable t) {
            AutoRoot.log(this, "boot UI video open failed: " + t);
            video.setVisibility(View.GONE);
        }
    }

    /**
     * Center-crops the video like ImageView's CENTER_CROP: size the view to
     * the aspect-correct rectangle that covers the screen, centered. This
     * needs the video dimensions, so it runs from onPrepared.
     */
    private void cropVideo(int videoW, int videoH) {
        if (video == null || videoW <= 0 || videoH <= 0) {
            return;
        }
        int screenW = getResources().getDisplayMetrics().widthPixels;
        int screenH = getResources().getDisplayMetrics().heightPixels;
        float scale = Math.max((float) screenW / videoW,
                (float) screenH / videoH);
        int width = Math.round(videoW * scale);
        int height = Math.round(videoH * scale);
        video.setLayoutParams(new FrameLayout.LayoutParams(width, height,
                Gravity.CENTER));
    }

    private final Runnable slide = new Runnable() {
        @Override
        public void run() {
            if (slides.isEmpty()) {
                return;
            }
            showSlide((slideIndex + 1) % slides.size());
        }
    };

    private void showSlide(int index) {
        slideIndex = index;
        if (image == null || slides.isEmpty()) {
            return;
        }
        Bitmap next = decode(slides.get(index));
        if (next == null) {
            return;
        }
        Bitmap old = slideBitmap;
        slideBitmap = next;
        image.setImageBitmap(next);
        image.setAlpha(0f);
        image.setScaleX(1f);
        image.setScaleY(1f);
        image.animate().alpha(1f).scaleX(1.06f).scaleY(1.06f)
                .setDuration(1400).start();
        if (old != null && old != next) {
            old.recycle();
        }
        ui.removeCallbacks(slide);
        if (slides.size() > 1) {
            ui.postDelayed(slide, 9000);
        }
    }

    private void update() {
        String text = AutoRoot.stageText(this);
        int state = AutoRoot.stageState(this);
        long since = AutoRoot.stageTime(this);
        boolean changed = !text.equals(lastText) || state != lastState;

        if (changed) {
            lastText = text;
            lastState = state;
            if (title != null) {
                if (state == AutoRoot.STAGE_OK) {
                    title.setText("Root ready");
                } else if (state == AutoRoot.STAGE_FAILED) {
                    title.setText("Auto-root failed");
                } else {
                    title.setText("TimerRoot");
                }
                subtitle.setText(shorten(text, 240));
                ring.setState(state);
            }
        }

        if (turnOffButton != null) {
            boolean show = state != AutoRoot.STAGE_OK && AutoRoot.isEnabled(this);
            turnOffButton.setVisibility(show ? View.VISIBLE : View.GONE);
        }

        if (detail != null) {
            long now = System.currentTimeMillis();
            long elapsed = since > 0 ? Math.max(0, now - since) : 0;
            String time = String.format(Locale.US, "%02d:%02d",
                    elapsed / 60000, (elapsed / 1000) % 60);
            if (state == AutoRoot.STAGE_OK) {
                detail.setText("completed");
            } else if (state == AutoRoot.STAGE_FAILED) {
                detail.setText("unlock and open TimerRoot to retry");
            } else {
                detail.setText("auto-root is running · " + time);
            }
        }

        if (hint != null) {
            if (userUnlocked) {
                hint.setText(state == AutoRoot.STAGE_RUNNING
                        ? "Unlocked. This screen stays open until the exploit finishes."
                        : "Unlocked. Tap Hide or it closes itself.");
            } else {
                hint.setText("Tap Hide to return to the lock screen (needed for a "
                        + "PIN or pattern); biometric unlock works without hiding.");
            }
        }

        if (state != AutoRoot.STAGE_RUNNING && userUnlocked && !finishScheduled
                && since >= created - 2000) {
            finishScheduled = true;
            ui.postDelayed(this::finishScreen, DONE_DELAY_MS);
        }
    }

    private void hide() {
        AutoRoot.hideBootUi(this);
        finish();
    }

    /**
     * Stops auto-root for future boots without touching the run in progress:
     * the root shell that is already alive stays alive. The button disappears
     * once the switch is off, and on the completed screen only Hide remains.
     */
    private void turnOff() {
        AutoRoot.setEnabled(this, false);
        AutoRoot.log(this, "auto-root disabled from the boot screen");
        toast("Auto-root is off for future boots");
        update();
    }

    private void finishScreen() {
        if (!isFinishing()) {
            finishAndRemoveTask();
        }
    }

    private boolean isUserUnlocked() {
        try {
            UserManager um = getSystemService(UserManager.class);
            return um == null || um.isUserUnlocked();
        } catch (Throwable t) {
            return false;
        }
    }

    // -------------------------------------------------------------- helpers

    private static List<File> imageFiles(File dir) {
        File[] all = dir.listFiles((d, name) -> name.startsWith(IMAGE_PREFIX));
        if (all == null) {
            return new ArrayList<>();
        }
        List<File> out = new ArrayList<>(Arrays.asList(all));
        out.sort(Comparator.comparing(File::getName));
        return out;
    }

    private Bitmap decode(File file) {
        try {
            BitmapFactory.Options bounds = new BitmapFactory.Options();
            bounds.inJustDecodeBounds = true;
            BitmapFactory.decodeFile(file.getAbsolutePath(), bounds);
            int width = Math.max(1, bounds.outWidth);
            int height = Math.max(1, bounds.outHeight);
            int sample = 1;
            int maxW = Math.max(getResources().getDisplayMetrics().widthPixels, 720);
            int maxH = Math.max(getResources().getDisplayMetrics().heightPixels, 1280);
            while (width / (sample * 2) >= maxW && height / (sample * 2) >= maxH) {
                sample *= 2;
            }
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inSampleSize = sample;
            return BitmapFactory.decodeFile(file.getAbsolutePath(), options);
        } catch (Throwable t) {
            AutoRoot.log(this, "boot UI image failed: " + t);
            return null;
        }
    }

    private static String shorten(String text, int max) {
        if (text == null) {
            return "";
        }
        String oneLine = text.replace('\n', ' ').trim();
        return oneLine.length() <= max ? oneLine
                : oneLine.substring(0, max - 3) + "...";
    }

    private TextView text(String value, int sp, int style, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        view.setTypeface(Typeface.create(Typeface.DEFAULT, style));
        view.setTextColor(color);
        view.setLineSpacing(dp(3), 1f);
        return view;
    }

    private TextView button(String label, View.OnClickListener listener) {
        TextView view = text(label, 14, Typeface.BOLD, 0xFFFFFFFF);
        view.setGravity(Gravity.CENTER);
        view.setPadding(dp(22), dp(11), dp(22), dp(11));
        GradientDrawable background = new GradientDrawable();
        background.setColor(0x99000000);
        background.setCornerRadius(dp(24));
        background.setStroke(dp(1), 0x44FFFFFF);
        view.setBackground(background);
        view.setOnClickListener(listener);
        return view;
    }

    private static FrameLayout.LayoutParams match() {
        return new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT);
    }

    private int dp(float value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value,
                getResources().getDisplayMetrics()));
    }

    private void toast(String text) {
        android.widget.Toast.makeText(this, text, android.widget.Toast.LENGTH_SHORT).show();
    }

    // ------------------------------------------------------------ decoration

    /** Slow animated gradient + drifting glows; ~20 fps, very cheap. */
    static final class Backdrop extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final long start = SystemClock.uptimeMillis();
        private final float[] dots = new float[96];
        private final Path path = new Path();
        private LinearGradient base;
        private RadialGradient glowA;
        private RadialGradient glowB;
        private boolean running = true;

        Backdrop(Context context) {
            super(context);
            setLayerType(LAYER_TYPE_HARDWARE, null);
            for (int i = 0; i < dots.length; i += 2) {
                dots[i] = (float) Math.random();
                dots[i + 1] = (float) Math.random();
            }
        }

        void setRunning(boolean running) {
            this.running = running;
            if (running) {
                invalidate();
            }
        }

        @Override
        protected void onSizeChanged(int w, int h, int oldw, int oldh) {
            super.onSizeChanged(w, h, oldw, oldh);
            base = new LinearGradient(0, 0, 0, Math.max(1, h),
                    new int[]{0xFF05090F, 0xFF081722, 0xFF030507},
                    new float[]{0f, 0.45f, 1f}, Shader.TileMode.CLAMP);
            glowA = new RadialGradient(0, 0, Math.max(1, w * 0.55f),
                    new int[]{0x3320B8A0, 0x00000000}, null, Shader.TileMode.CLAMP);
            glowB = new RadialGradient(0, 0, Math.max(1, w * 0.45f),
                    new int[]{0x2A2C6FD6, 0x00000000}, null, Shader.TileMode.CLAMP);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            int w = getWidth();
            int h = getHeight();
            if (w == 0 || h == 0) {
                return;
            }
            long t = SystemClock.uptimeMillis() - start;

            if (base != null) {
                paint.setShader(base);
                canvas.drawRect(0, 0, w, h, paint);
            }

            float ax = w * 0.22f + (float) Math.sin(t / 9000.0) * w * 0.16f;
            float ay = h * 0.30f + (float) Math.cos(t / 11000.0) * h * 0.10f;
            if (glowA != null) {
                paint.setShader(glowA);
                canvas.save();
                canvas.translate(ax, ay);
                canvas.drawRect(ax - w, ay - w, ax + w, ay + w, paint);
                canvas.restore();
            }

            float bx = w * 0.78f + (float) Math.cos(t / 13000.0) * w * 0.14f;
            float by = h * 0.62f + (float) Math.sin(t / 8000.0) * h * 0.12f;
            if (glowB != null) {
                paint.setShader(glowB);
                canvas.save();
                canvas.translate(bx, by);
                canvas.drawRect(bx - w, by - w, bx + w, by + w, paint);
                canvas.restore();
            }

            paint.setShader(null);
            for (int i = 0; i < dots.length; i += 2) {
                float x = dots[i] * w;
                float y = dots[i + 1] * h;
                float twinkle = 0.35f + 0.65f * (0.5f + 0.5f
                        * (float) Math.sin(t / 1700.0 + i));
                paint.setColor((((int) (twinkle * 60)) << 24) | 0x9FD8FF);
                canvas.drawCircle(x, y, 1.6f, paint);
            }

            if (running) {
                postInvalidateDelayed(50);
            }
        }
    }

    /** Soft black fade behind the text panel. */
    static final class Scrim extends View {
        private final Paint paint = new Paint();

        Scrim(Context context) {
            super(context);
        }

        @Override
        protected void onSizeChanged(int w, int h, int oldw, int oldh) {
            super.onSizeChanged(w, h, oldw, oldh);
            paint.setShader(new LinearGradient(0, 0, 0, Math.max(1, h),
                    new int[]{0x00000000, 0x00000000, 0xE6000000},
                    new float[]{0f, 0.42f, 1f}, Shader.TileMode.CLAMP));
        }

        @Override
        protected void onDraw(Canvas canvas) {
            canvas.drawRect(0, 0, getWidth(), getHeight(), paint);
        }
    }

    /** Spinning ring while running, check mark on success, cross on failure. */
    static final class Ring extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF oval = new RectF();
        private final Path path = new Path();
        private final long start = SystemClock.uptimeMillis();
        private boolean running = true;
        private int state = AutoRoot.STAGE_RUNNING;

        Ring(Context context) {
            super(context);
            setLayerType(LAYER_TYPE_HARDWARE, null);
            paint.setStyle(Paint.Style.STROKE);
        }

        void setState(int state) {
            if (this.state != state) {
                this.state = state;
                invalidate();
            }
        }

        void setRunning(boolean running) {
            this.running = running;
            if (running) {
                invalidate();
            }
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float w = getWidth();
            float h = getHeight();
            float cx = w / 2f;
            float cy = h / 2f;
            float stroke = Math.max(3f, w * 0.055f);
            float r = Math.min(w, h) / 2f - stroke * 2;
            oval.set(cx - r, cy - r, cx + r, cy + r);

            paint.setShader(null);
            paint.setStrokeWidth(stroke);
            paint.setColor(0x22FFFFFF);
            canvas.drawArc(oval, 0, 360, false, paint);

            if (state == AutoRoot.STAGE_OK) {
                paint.setColor(0xFF2FD06B);
                paint.setStrokeCap(Paint.Cap.ROUND);
                canvas.drawArc(oval, 0, 360, false, paint);
                path.reset();
                path.moveTo(cx - r * 0.42f, cy + r * 0.02f);
                path.lineTo(cx - r * 0.10f, cy + r * 0.34f);
                path.lineTo(cx + r * 0.46f, cy - r * 0.34f);
                paint.setStrokeWidth(stroke * 0.9f);
                canvas.drawPath(path, paint);
            } else if (state == AutoRoot.STAGE_FAILED) {
                paint.setColor(0xFFFF5C5C);
                paint.setStrokeCap(Paint.Cap.ROUND);
                canvas.drawArc(oval, 0, 360, false, paint);
                float d = r * 0.34f;
                canvas.drawLine(cx - d, cy - d, cx + d, cy + d, paint);
                canvas.drawLine(cx + d, cy - d, cx - d, cy + d, paint);
            } else {
                long t = SystemClock.uptimeMillis() - start;
                float angle = (t % 1300) * 360f / 1300f;
                paint.setColor(0xFF5CC8FF);
                paint.setStrokeCap(Paint.Cap.ROUND);
                canvas.drawArc(oval, angle, 110, false, paint);
                paint.setColor(0x555CC8FF);
                paint.setStrokeWidth(stroke * 0.55f);
                // Faint tail just behind the bright arc, not opposite it.
                canvas.drawArc(oval, angle - 52, 42, false, paint);
            }

            if (running) {
                postInvalidateDelayed(16);
            }
        }
    }
}
