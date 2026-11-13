package com.kpgc.timerroot;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.provider.Settings;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Toast;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import rikka.shizuku.Shizuku;

/**
 * Front end for CVE-2026-98260 (posix CPU timer UAF).
 *
 * The exploit cannot run in this process (an app is untrusted_app and cannot
 * read /sys/kernel/tracing), so it runs through a Shizuku user service that
 * Shizuku starts as the shell user (uid 2000, u:r:shell:s0).
 */
public class MainActivity extends Activity {

    private static final String TAG = "TimerRoot";
    private static final int REQUEST_CODE = 1001;
    private static final int REQUEST_NOTIFICATIONS = 1002;
    private static final int REQUEST_BOOT_MEDIA = 1003;
    /**
     * Prebuilt exploit for this exact device build. The upstream timer/timer
     * targets a 6.12.69 OnePlus kernel and must not be used here: its timer
     * call site, cred layout and task offsets are all different.
     */
    private static final String TIMER_URL =
            "https://github.com/MVN123123123123123/TimerRoot/releases/download/bingchiling/timer";
    private static final String TIMER_TARGET = "target=lynx";

    private static final int BG = 0xFF0B0B0B;
    private static final int CARD = 0xFF1A1A1C;
    private static final int CARD_RAISED = 0xFF232326;
    private static final int LINE = 0xFF2C2C30;
    private static final int TEXT = 0xFFFFFFFF;
    private static final int MUTED = 0xFF8E8E96;
    private static final int GREEN = 0xFF2FD06B;
    private static final int ON_GREEN = 0xFF04140A;
    private static final int GREEN_DARK = 0xFF123D24;
    private static final int RED = 0xFFFF5C5C;
    private static final int TAB_BAR_HEIGHT = 62;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat clock = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private IUserService service;
    private boolean bound;
    private boolean rootOpen;
    private boolean downloading;
    private Runnable pendingServiceAction;

    private LinearLayout statusCard;
    private TextView statusTitle;
    private TextView statusSubtitle;
    private TextView statusBadge;
    private TextView detailModel;
    private TextView detailMode;
    private TextView detailKernel;
    private TextView detailKsud;
    private TextView detailKsu;
    private TextView detailSelinux;
    private TextView detailSeccomp;
    private TextView logText;
    private ScrollView logScroll;
    private LinearLayout homePage;
    private LinearLayout logPage;
    private LinearLayout settingsPage;
    private final TextView[] tabLabels = new TextView[3];
    private final View[] tabIndicators = new View[3];
    private TextView autoToggle;
    private TextView samsungToggle;
    private TextView bootToggle;
    private TextView softToggle;
    private TextView updateToggle;
    private TextView updateStatus;
    private TextView updateBannerTitle;
    private TextView updateBannerDetail;
    private LinearLayout updateBanner;
    private volatile int latestKnownCode;
    private boolean updateChecking;
    private String installedVersion = "?";
    private String ksud = "-";
    private String ksu = "unknown";
    private String selinux = "-";
    private String seccomp = "-";

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            service = IUserService.Stub.asInterface(binder);
            bound = true;
            addLog("user service connected");
            applySamsungModeToService();
            refreshDetails();
            if (pendingServiceAction != null) {
                Runnable action = pendingServiceAction;
                pendingServiceAction = null;
                ui.post(action);
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            service = null;
            bound = false;
            addLog("user service disconnected");
            refreshDetails();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "onCreate");

        final FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(BG);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(0, insets.getSystemWindowInsetTop(), 0,
                    insets.getSystemWindowInsetBottom());
            return insets;
        });

        homePage = buildHome();
        logPage = buildLog();
        settingsPage = buildSettings();
        logPage.setVisibility(View.GONE);
        settingsPage.setVisibility(View.GONE);

        FrameLayout.LayoutParams fill = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
        fill.bottomMargin = dp(TAB_BAR_HEIGHT);
        root.addView(homePage, fill);
        root.addView(logPage, fill);
        root.addView(settingsPage, fill);

        LinearLayout bottom = buildBottomBar();
        FrameLayout.LayoutParams barParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(TAB_BAR_HEIGHT), Gravity.BOTTOM);
        root.addView(bottom, barParams);

        setContentView(root);
        showTab(0);
        refreshDetails();
        addLog("TimerRoot ready");
        updateAutoRootUi();
        updateUpdateUi();
        maybeAutoCheckUpdates();
        if (safePing() && safePermission() == 0) {
            bindService();
        }
    }

    // ------------------------------------------------------------------ UI

    private LinearLayout buildHome() {
        LinearLayout page = page();

        LinearLayout body = scrollBody(page);
        body.addView(pageHeader("TimerRoot",
                "CVE-2026-98260 · root shell & KernelSU"));

        body.addView(spacer(20));
        updateBanner = buildUpdateBanner();
        updateBanner.setVisibility(View.GONE);
        body.addView(updateBanner);

        body.addView(spacer(20));

        statusCard = new LinearLayout(this);
        statusCard.setOrientation(LinearLayout.HORIZONTAL);
        statusCard.setGravity(Gravity.CENTER_VERTICAL);
        statusCard.setPadding(dp(20), dp(20), dp(20), dp(20));
        statusCard.setBackground(cardBackground(CARD));

        LinearLayout texts = new LinearLayout(this);
        texts.setOrientation(LinearLayout.VERTICAL);
        TextView label = new TextView(this);
        label.setText("STATUS");
        label.setTextColor(0x99FFFFFF);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        label.setTypeface(Typeface.DEFAULT_BOLD);
        label.setLetterSpacing(0.16f);
        statusTitle = new TextView(this);
        statusTitle.setText("Not connected");
        statusTitle.setTextColor(TEXT);
        statusTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        statusTitle.setTypeface(Typeface.DEFAULT_BOLD);
        statusSubtitle = new TextView(this);
        statusSubtitle.setText("Start Shizuku first");
        statusSubtitle.setTextColor(0xFFB8B8C0);
        statusSubtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        statusSubtitle.setLineSpacing(dp(2), 1f);
        texts.addView(label);
        texts.addView(spacer(6));
        texts.addView(statusTitle);
        texts.addView(spacer(4));
        texts.addView(statusSubtitle);
        statusCard.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        statusBadge = new TextView(this);
        statusBadge.setGravity(Gravity.CENTER);
        statusBadge.setMinWidth(dp(58));
        statusBadge.setMinHeight(dp(58));
        statusBadge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 28);
        statusBadge.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams badgeParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        badgeParams.leftMargin = dp(14);
        statusCard.addView(statusBadge, badgeParams);
        body.addView(statusCard);

        addSection(body, "Actions");
        body.addView(primaryButton("Get root shell", v -> confirmRoot()));
        body.addView(spacer(10));
        body.addView(secondaryButton("Load KernelSU", v -> confirmKsu()));
        body.addView(spacer(10));
        body.addView(dangerButton("Stop root", v -> stopRoot()));

        addSection(body, "Device");
        LinearLayout details = card();
        detailMode = addRow(details, "MODE", "-", true);
        detailModel = addRow(details, "MODEL", "-", true);
        detailKernel = addRow(details, "KERNEL", "-", true);
        detailKsud = addRow(details, "KSUD", "-", true);
        detailKsu = addRow(details, "KERNELSU", "-", true);
        detailSelinux = addRow(details, "SELINUX", "-", true);
        detailSeccomp = addRow(details, "SECCOMP", "-", false);
        body.addView(details);

        addSection(body, "Tools");
        body.addView(buttonRow(
                compactButton("Shizuku", v -> showShizuku()),
                compactButton("Diagnose", v -> run("ids", "ids"))));

        body.addView(spacer(24));
        body.addView(hintCard("First run: start Shizuku, grant access, then press "
                + "Get root shell. Prepare or download the exploit binary under Settings."));

        return page;
    }

    private LinearLayout buildSettings() {
        LinearLayout page = page();

        LinearLayout body = scrollBody(page);
        body.addView(pageHeader("Settings",
                "Automation, boot screen and maintenance"));

        addSection(body, "Shizuku");
        LinearLayout shizuku = paddedCard();
        shizuku.addView(bodyText("Shizuku runs the exploit as the shell user. "
                + "Start it from its app, then grant TimerRoot access here."));
        shizuku.addView(spacer(14));
        shizuku.addView(compactButton("Check & grant access", v -> showShizuku()));
        body.addView(shizuku);

        addSection(body, "Exploit");
        LinearLayout exploit = paddedCard();
        exploit.addView(bodyText("The binary is built for this kernel. Prepare "
                + "installs the copy bundled in the APK; Download fetches the latest "
                + "build from GitHub."));
        exploit.addView(spacer(14));
        exploit.addView(buttonRow(
                compactButton("Prepare binary", v -> prepare()),
                compactButton("Download exploit", v -> downloadTimer())));
        body.addView(exploit);

        addSection(body, "Device mode");
        LinearLayout samsungCard = card();
        samsungToggle = addToggleRow(samsungCard, "Samsung mode",
                "DEFEX/KDP chain for Samsung kernels (auto-detected)",
                v -> toggleSamsungMode());
        body.addView(samsungCard);
        body.addView(spacer(10));
        body.addView(compactButton("Use automatic detection",
                v -> useAutoSamsungMode()));
        body.addView(spacer(12));
        body.addView(hintCard("Samsung mode is selected automatically on "
                + "Samsung devices. It is pinned to the diabl0w/KernelSU "
                + "Samsung build: the app bundles that ksud, clears the DEFEX "
                + "creds hash and execs ksud through a KDP-safe mount. A "
                + "different KernelSU manager is rejected. Turn it off to use "
                + "the generic profile on a Samsung device, or on to try the "
                + "Samsung chain elsewhere."));

        addSection(body, "Auto-root");
        LinearLayout autoCard = card();
        autoToggle = addToggleRow(autoCard, "Auto-root",
                "Run the exploit on every boot", v -> toggleAutoRoot());
        body.addView(autoCard);
        body.addView(spacer(10));
        body.addView(buttonRow(
                compactButton("Run now", v -> confirmAutoRootNow()),
                compactButton("Install channel", v -> installChannel())));
        body.addView(spacer(10));
        body.addView(compactButton("View auto-root log", v -> {
            addLog(AutoRoot.readLog(this).isEmpty() ? "auto-root log is empty"
                    : AutoRoot.readLog(this));
            showTab(1);
        }));
        body.addView(spacer(12));
        body.addView(hintCard("Auto-root reruns the exploit once per real boot. "
                + "Install the channel once so later boots can reach Shizuku without "
                + "Wi-Fi; unlocking is still required."));

        addSection(body, "Boot screen");
        LinearLayout bootCard = card();
        bootToggle = addToggleRow(bootCard, "Boot status screen",
                "Show progress over the lock screen", v -> toggleBootUi());
        body.addView(bootCard);
        body.addView(spacer(10));
        body.addView(buttonRow(
                compactButton("Background", v -> pickBootMedia()),
                compactButton("Preview", v -> previewBootUi())));
        body.addView(spacer(10));
        body.addView(buttonRow(
                compactButton("Allow overlay", v -> requestOverlay()),
                compactButton("Full-screen", v -> requestFullScreen())));
        body.addView(spacer(10));
        body.addView(compactButton("Clear background", v -> clearBootMedia()));
        body.addView(spacer(12));
        body.addView(hintCard("The background is copied into device-protected "
                + "storage, so it can be shown while the device is still locked."));

        addSection(body, "Restart");
        LinearLayout softCard = card();
        softToggle = addToggleRow(softCard, "Auto soft restart",
                "Restart Android after a successful root", v -> toggleSoftRestart());
        body.addView(softCard);
        body.addView(spacer(10));
        body.addView(secondaryButton("Restart Android", v -> confirmSoftRestart()));
        body.addView(spacer(10));
        body.addView(dangerButton("Reboot device", v -> reboot()));
        body.addView(spacer(12));
        body.addView(hintCard("A soft restart keeps the kernel and root alive while "
                + "reloading modules and Zygisk. It closes every app and takes about a minute."));

        addSection(body, "Updates");
        LinearLayout updateCard = card();
        updateToggle = addToggleRow(updateCard, "Check for updates",
                "Look for a newer build once a day", v -> toggleAutoUpdate());
        body.addView(updateCard);
        body.addView(spacer(10));
        updateStatus = bodyText("Not checked yet.");
        LinearLayout statusCardUpdate = paddedCard();
        statusCardUpdate.addView(updateStatus);
        body.addView(statusCardUpdate);
        body.addView(spacer(10));
        body.addView(buttonRow(
                compactButton("Check now", v -> checkForUpdates()),
                compactButton("Open releases", v -> openReleases())));

        body.addView(spacer(28));
        TextView footer = new TextView(this);
        footer.setText("TimerRoot " + versionName() + " · CVE-2026-98260");
        footer.setTextColor(0xFF6E6E76);
        footer.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        footer.setGravity(Gravity.CENTER);
        body.addView(footer);
        body.addView(spacer(8));

        return page;
    }

    private LinearLayout buildLog() {
        LinearLayout page = page();
        page.setPadding(dp(20), dp(16), dp(20), dp(16));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);

        LinearLayout titles = new LinearLayout(this);
        titles.setOrientation(LinearLayout.VERTICAL);
        TextView title = new TextView(this);
        title.setText("Log");
        title.setTextColor(TEXT);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 30);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        TextView subtitle = new TextView(this);
        subtitle.setText("App and shell service activity");
        subtitle.setTextColor(MUTED);
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        titles.addView(title);
        titles.addView(subtitle);
        header.addView(titles, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(compactButton("Copy", v -> copyLog()),
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
        header.addView(hspace(8));
        header.addView(compactButton("Clear", v -> {
            logText.setText("");
            addLog("log cleared");
        }), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        page.addView(header);
        page.addView(spacer(16));

        logText = new TextView(this);
        logText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        logText.setTypeface(Typeface.MONOSPACE);
        logText.setTextColor(0xFFD6D6D6);
        logText.setTextIsSelectable(true);
        logText.setLineSpacing(dp(2), 1f);
        logScroll = new ScrollView(this);
        logScroll.setFillViewport(true);
        logScroll.setVerticalScrollBarEnabled(false);
        LinearLayout card = card();
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        card.addView(logText);
        logScroll.addView(card, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        page.addView(logScroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return page;
    }

    private LinearLayout buildBottomBar() {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setBackgroundColor(0xFF131315);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(8), 0, dp(8), 0);
        addTab(bar, 0, "Home", v -> showTab(0));
        addTab(bar, 1, "Log", v -> showTab(1));
        addTab(bar, 2, "Settings", v -> showTab(2));
        return bar;
    }

    private void addTab(LinearLayout bar, int index, String label,
                        View.OnClickListener click) {
        LinearLayout tab = new LinearLayout(this);
        tab.setOrientation(LinearLayout.VERTICAL);
        tab.setGravity(Gravity.CENTER);
        tab.setOnClickListener(click);

        TextView text = new TextView(this);
        text.setText(label);
        text.setTextColor(MUTED);
        text.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        text.setGravity(Gravity.CENTER);
        tab.addView(text);

        View indicator = new View(this);
        GradientDrawable dot = new GradientDrawable();
        dot.setColor(GREEN);
        dot.setCornerRadius(dp(2));
        indicator.setBackground(dot);
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(
                dp(18), dp(3));
        dotParams.topMargin = dp(6);
        tab.addView(indicator, dotParams);

        bar.addView(tab, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.MATCH_PARENT, 1f));
        tabLabels[index] = text;
        tabIndicators[index] = indicator;
    }

    private void showTab(int index) {
        homePage.setVisibility(index == 0 ? View.VISIBLE : View.GONE);
        logPage.setVisibility(index == 1 ? View.VISIBLE : View.GONE);
        settingsPage.setVisibility(index == 2 ? View.VISIBLE : View.GONE);
        for (int i = 0; i < tabLabels.length; i++) {
            boolean active = i == index;
            tabLabels[i].setTextColor(active ? GREEN : MUTED);
            tabLabels[i].setTypeface(active
                    ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
            tabIndicators[i].setVisibility(active
                    ? View.VISIBLE : View.INVISIBLE);
        }
    }

    // ------------------------------------------------------------ widgets

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density);
    }

    private LinearLayout page() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setBackgroundColor(BG);
        return page;
    }

    private LinearLayout scrollBody(LinearLayout page) {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setVerticalScrollBarEnabled(false);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(20), dp(16), dp(20), dp(28));
        scroll.addView(body, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        page.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        return body;
    }

    private LinearLayout pageHeader(String title, String subtitle) {
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.VERTICAL);
        TextView name = new TextView(this);
        name.setText(title);
        name.setTextColor(TEXT);
        name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 30);
        name.setTypeface(Typeface.DEFAULT_BOLD);
        TextView sub = new TextView(this);
        sub.setText(subtitle);
        sub.setTextColor(MUTED);
        sub.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        sub.setLineSpacing(dp(2), 1f);
        header.addView(name);
        header.addView(spacer(6));
        header.addView(sub);
        return header;
    }

    private View spacer(int height) {
        View view = new View(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(height)));
        return view;
    }

    private View hspace(int width) {
        View view = new View(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(dp(width), 1));
        return view;
    }

    private TextView sectionLabel(String text) {
        TextView view = new TextView(this);
        view.setText(text.toUpperCase(Locale.US));
        view.setTextColor(MUTED);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setLetterSpacing(0.14f);
        return view;
    }

    private void addSection(LinearLayout body, String title) {
        body.addView(spacer(26));
        body.addView(sectionLabel(title));
        body.addView(spacer(10));
    }

    private LinearLayout card() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(cardBackground(CARD));
        return card;
    }

    private LinearLayout paddedCard() {
        LinearLayout card = card();
        card.setPadding(dp(18), dp(18), dp(18), dp(18));
        return card;
    }

    private LinearLayout hintCard(String text) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xFF141416);
        bg.setCornerRadius(dp(18));
        bg.setStroke(dp(1), LINE);
        card.setBackground(bg);
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        card.addView(bodyText(text));
        return card;
    }

    /**
     * Green-tinted banner on Home announcing a newer release. Hidden until a
     * check actually finds one, so Home stays unchanged for most users.
     */
    private LinearLayout buildUpdateBanner() {
        LinearLayout banner = new LinearLayout(this);
        banner.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xFF0F2E1E);
        bg.setCornerRadius(dp(22));
        bg.setStroke(dp(1), 0xFF24563A);
        banner.setBackground(bg);
        banner.setPadding(dp(18), dp(16), dp(18), dp(16));

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.HORIZONTAL);
        top.setGravity(Gravity.CENTER_VERTICAL);

        LinearLayout texts = new LinearLayout(this);
        texts.setOrientation(LinearLayout.VERTICAL);
        updateBannerTitle = new TextView(this);
        updateBannerTitle.setText("Update available");
        updateBannerTitle.setTextColor(TEXT);
        updateBannerTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        updateBannerTitle.setTypeface(Typeface.DEFAULT_BOLD);
        updateBannerDetail = new TextView(this);
        updateBannerDetail.setText("");
        updateBannerDetail.setTextColor(0xFFA8CFB8);
        updateBannerDetail.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        updateBannerDetail.setLineSpacing(dp(2), 1f);
        LinearLayout.LayoutParams detailParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        detailParams.topMargin = dp(3);
        texts.addView(updateBannerTitle);
        texts.addView(updateBannerDetail, detailParams);
        top.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView dismiss = new TextView(this);
        dismiss.setText("Dismiss");
        dismiss.setTextColor(0xFFA8CFB8);
        dismiss.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        dismiss.setTypeface(Typeface.DEFAULT_BOLD);
        dismiss.setGravity(Gravity.CENTER);
        dismiss.setPadding(dp(12), dp(8), dp(12), dp(8));
        dismiss.setBackground(pressable(roundRect(0xFF1D4A32, 14, 0)));
        dismiss.setOnClickListener(v -> {
            if (latestKnownCode > 0) {
                UpdateChecker.dismiss(this, latestKnownCode);
            }
            updateBanner.setVisibility(View.GONE);
        });
        top.addView(dismiss, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        banner.addView(top);

        banner.addView(spacer(14));
        banner.addView(primaryButton("Get the update", v -> openReleases()));
        return banner;
    }

    private TextView bodyText(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(0xFFB0B0B8);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        view.setLineSpacing(dp(3), 1f);
        return view;
    }

    private GradientDrawable cardBackground(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(22));
        if (color == GREEN_DARK) {
            drawable.setGradientType(GradientDrawable.LINEAR_GRADIENT);
            drawable.setOrientation(GradientDrawable.Orientation.LEFT_RIGHT);
            drawable.setColors(new int[]{0xFF0F3A22, 0xFF1E7A46});
        }
        return drawable;
    }

    private GradientDrawable roundRect(int color, int radius, int stroke) {
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(color);
        bg.setCornerRadius(dp(radius));
        if (stroke != 0) {
            bg.setStroke(dp(1), stroke);
        }
        return bg;
    }

    private Drawable pressable(Drawable content) {
        return new RippleDrawable(ColorStateList.valueOf(0x24FFFFFF), content, null);
    }

    private TextView button(String text, int background, int color, int stroke,
                            int textSize, int padH, int padV, int radius,
                            int minHeight, View.OnClickListener click) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, textSize);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setGravity(Gravity.CENTER);
        view.setPadding(dp(padH), dp(padV), dp(padH), dp(padV));
        view.setMinHeight(dp(minHeight));
        view.setBackground(pressable(roundRect(background, radius, stroke)));
        view.setOnClickListener(click);
        view.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        return view;
    }

    private TextView primaryButton(String text, View.OnClickListener click) {
        return button(text, GREEN, ON_GREEN, 0, 15, 18, 16, 18, 54, click);
    }

    private TextView secondaryButton(String text, View.OnClickListener click) {
        return button(text, CARD, TEXT, LINE, 15, 18, 16, 18, 54, click);
    }

    private TextView dangerButton(String text, View.OnClickListener click) {
        return button(text, CARD, RED, 0xFF3A2222, 15, 18, 16, 18, 54, click);
    }

    private TextView compactButton(String text, View.OnClickListener click) {
        return button(text, CARD_RAISED, TEXT, LINE, 13, 14, 10, 14, 44, click);
    }

    private LinearLayout buttonRow(TextView left, TextView right) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams leftParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        leftParams.rightMargin = dp(10);
        row.addView(left, leftParams);
        row.addView(right, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private TextView addToggleRow(LinearLayout parent, String title, String subtitle,
                                  View.OnClickListener click) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(18), dp(15), dp(18), dp(15));
        row.setOnClickListener(click);

        LinearLayout texts = new LinearLayout(this);
        texts.setOrientation(LinearLayout.VERTICAL);
        TextView name = new TextView(this);
        name.setText(title);
        name.setTextColor(TEXT);
        name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        name.setTypeface(Typeface.DEFAULT_BOLD);
        texts.addView(name);

        TextView sub = new TextView(this);
        sub.setText(subtitle);
        sub.setTextColor(MUTED);
        sub.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        sub.setLineSpacing(dp(2), 1f);
        LinearLayout.LayoutParams subParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        subParams.topMargin = dp(3);
        texts.addView(sub, subParams);
        row.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView state = new TextView(this);
        state.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        state.setTypeface(Typeface.DEFAULT_BOLD);
        state.setGravity(Gravity.CENTER);
        state.setPadding(dp(12), dp(6), dp(12), dp(6));
        state.setMinWidth(dp(52));
        LinearLayout.LayoutParams stateParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        stateParams.leftMargin = dp(12);
        row.addView(state, stateParams);

        /*
         * The card holds a single row, so the press feedback can reuse the
         * card's own rounded shape as both content and ripple mask.
         */
        row.setBackground(new RippleDrawable(
                ColorStateList.valueOf(0x1FFFFFFF),
                roundRect(CARD, 22, 0),
                roundRect(0xFFFFFFFF, 22, 0)));
        parent.addView(row);
        setToggleState(state, false);
        return state;
    }

    private void setToggleState(TextView view, boolean on) {
        view.setText(on ? "ON" : "OFF");
        view.setTextColor(on ? ON_GREEN : MUTED);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(on ? GREEN : CARD_RAISED);
        bg.setCornerRadius(dp(20));
        view.setBackground(bg);
    }

    private void styleBadge(String text, int color) {
        if (statusBadge == null) {
            return;
        }
        statusBadge.setText(text);
        statusBadge.setTextColor(color);
        GradientDrawable bg = new GradientDrawable();
        bg.setShape(GradientDrawable.OVAL);
        // Same hue as the glyph, at a low alpha so the badge stays quiet.
        bg.setColor((color & 0x00FFFFFF) | 0x33000000);
        statusBadge.setBackground(bg);
    }

    private TextView addRow(LinearLayout parent, String label, String value,
                            boolean divider) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(dp(18), dp(13), dp(18), dp(13));

        TextView name = new TextView(this);
        name.setText(label);
        name.setTextColor(MUTED);
        name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        name.setTypeface(Typeface.DEFAULT_BOLD);
        name.setLetterSpacing(0.1f);

        TextView val = new TextView(this);
        val.setText(value);
        val.setTextColor(TEXT);
        val.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        val.setLineSpacing(dp(2), 1f);

        row.addView(name);
        row.addView(spacer(4));
        row.addView(val);
        parent.addView(row);
        if (divider) {
            View line = new View(this);
            line.setBackgroundColor(LINE);
            LinearLayout.LayoutParams lineParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, 1);
            lineParams.leftMargin = dp(18);
            lineParams.rightMargin = dp(18);
            parent.addView(line, lineParams);
        }
        return val;
    }

    private String versionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Throwable t) {
            return "0.39";
        }
    }

    // ------------------------------------------------------------- updates

    /** Reflects the stored update settings; called on create and on resume. */
    private void updateUpdateUi() {
        if (updateToggle == null) {
            return;
        }
        setToggleState(updateToggle, UpdateChecker.isAutoEnabled(this));
        // Paint the banner from the last check so it survives a relaunch even
        // when the daily interval has not elapsed yet.
        if (updateBanner != null) {
            boolean cached = UpdateChecker.hasCachedUpdate(this);
            if (cached) {
                latestKnownCode = UpdateChecker.cachedLatestCode(this);
                showUpdateBanner(UpdateChecker.cachedLatestName(this),
                        latestKnownCode);
            }
            updateBanner.setVisibility(cached ? View.VISIBLE : View.GONE);
        }
        if (updateStatus == null) {
            return;
        }
        long last = UpdateChecker.lastCheck(this);
        String message = UpdateChecker.lastMessage(this);
        if (last == 0 || message == null) {
            updateStatus.setText("Installed " + versionName()
                    + ". Automatic checks run at most once a day while the app "
                    + "is open.");
            return;
        }
        String when = android.text.format.DateUtils.getRelativeTimeSpanString(
                last, System.currentTimeMillis(),
                android.text.format.DateUtils.MINUTE_IN_MILLIS).toString();
        updateStatus.setText(capitalize(message) + ".\nLast checked " + when
                + ". Installed " + versionName() + ".");
    }

    private void toggleAutoUpdate() {
        boolean enabled = !UpdateChecker.isAutoEnabled(this);
        UpdateChecker.setAutoEnabled(this, enabled);
        updateUpdateUi();
        addLog("automatic update checks " + (enabled ? "enabled" : "disabled"));
        if (enabled) {
            maybeAutoCheckUpdates();
        }
    }

    /**
     * Runs a silent check when auto-checks are on and the last one is more
     * than a day old. A check fetches the small release APK when the release
     * changed, which is what makes the version comparison trustworthy.
     */
    private void maybeAutoCheckUpdates() {
        if (!UpdateChecker.isAutoEnabled(this) || !UpdateChecker.isCheckDue(this)) {
            return;
        }
        runUpdateCheck(false);
    }

    /** The manual button: one at a time, with a toast telling it is running. */
    private void checkForUpdates() {
        if (updateChecking) {
            toast("A check is already running");
            return;
        }
        runUpdateCheck(true);
    }

    private void runUpdateCheck(boolean manual) {
        if (updateChecking) {
            return;
        }
        updateChecking = true;
        if (updateStatus != null && manual) {
            updateStatus.setText("Checking GitHub…");
        }
        new Thread(() -> {
            UpdateChecker.Result result = UpdateChecker.check(this);
            ui.post(() -> {
                updateChecking = false;
                addLog("update check: " + result.message);
                applyUpdateResult(result, manual);
                updateUpdateUi();
            });
        }).start();
    }

    private void showUpdateBanner(String remoteVersion, int remoteCode) {
        if (updateBannerTitle == null || updateBannerDetail == null) {
            return;
        }
        updateBannerTitle.setText("A newer build is available");
        updateBannerDetail.setText("Version "
                + UpdateChecker.versionLabel(remoteVersion, remoteCode)
                + " · you have " + versionName());
    }

    private void applyUpdateResult(UpdateChecker.Result result, boolean manual) {
        latestKnownCode = result.remoteCode;
        boolean show = result.available
                && !UpdateChecker.isDismissed(this, result.remoteCode);
        if (updateBanner != null) {
            if (show) {
                showUpdateBanner(result.remoteVersion, result.remoteCode);
            }
            updateBanner.setVisibility(show ? View.VISIBLE : View.GONE);
        }
        if (manual) {
            toast(result.available
                    ? "Update available: " + UpdateChecker.versionLabel(
                    result.remoteVersion, result.remoteCode)
                    : result.message);
        }
    }

    private static String capitalize(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        return Character.toUpperCase(text.charAt(0)) + text.substring(1);
    }

    private void openReleases() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW,
                    Uri.parse(UpdateChecker.RELEASES_PAGE)));
        } catch (Throwable t) {
            addLog("could not open the releases page: " + t);
            toast("No browser available");
        }
    }

    // ------------------------------------------------------------- state

    private void refreshDetails() {
        detailModel.setText(Build.MODEL + " / " + Build.PRODUCT);
        detailKernel.setText(System.getProperty("os.version", "?"));
        if (service != null) {
            new Thread(() -> {
                try {
                    parseInfo(service.info());
                    ui.post(this::applyDetails);
                } catch (Throwable t) {
                    Log.i(TAG, "info failed: " + t);
                }
            }).start();
        }
        applyDetails();
    }

    private void parseInfo(String raw) {
        for (String line : raw.split("\n")) {
            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = line.substring(0, eq);
            String value = line.substring(eq + 1).trim();
            if (key.equals("selinux")) {
                selinux = value;
            } else if (key.equals("seccomp")) {
                seccomp = value;
            } else if (key.equals("ksud")) {
                ksud = value;
            } else if (key.equals("ksu")) {
                ksu = value;
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateAutoRootUi();
        updateUpdateUi();
        maybeAutoCheckUpdates();
        refreshDetails();
    }

    private void applyDetails() {
        if (statusCard != null) {
            statusCard.setBackground(cardBackground(
                    rootOpen || "active".equals(ksu) ? GREEN_DARK : CARD));
        }
        if (detailMode != null) {
            detailMode.setText(AutoRoot.isSamsungMode(this)
                    ? "Samsung (DEFEX/KDP chain)" : "Generic (kernel conf)");
        }
        detailKsud.setText(ksud);
        detailKsu.setText("active".equals(ksu) ? "jailbreak mode (u:r:ksu:s0)" : ksu);
        detailSelinux.setText(selinux);
        detailSeccomp.setText(seccomp);
        boolean shizuku = safePing();
        if ("active".equals(ksu)) {
            statusTitle.setText("Jailbreak mode");
            statusSubtitle.setText("KernelSU loaded · su in u:r:ksu:s0 · gone after reboot");
            styleBadge("\u2713", TEXT);
        } else if (rootOpen) {
            statusTitle.setText("Root shell");
            statusSubtitle.setText("uid=0 · u:r:shell:s0 · gone after reboot");
            styleBadge("\u2713", TEXT);
        } else if (shizuku && bound) {
            statusTitle.setText("Ready");
            statusSubtitle.setText("Shizuku connected · no root yet");
            styleBadge("\u2022", MUTED);
        } else {
            statusTitle.setText("Not connected");
            statusSubtitle.setText(shizuku
                    ? (safePermission() == 0
                        ? "Shizuku is running · connecting..."
                        : "Shizuku is running · grant permission")
                    : "Start Shizuku first");
            styleBadge("?", MUTED);
        }
    }

    private boolean safePing() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable t) {
            return false;
        }
    }

    private void showShizuku() {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append("running: ").append(Shizuku.pingBinder()).append('\n');
            sb.append("permission: ").append(Shizuku.checkSelfPermission()).append('\n');
            sb.append("pre-v11: ").append(Shizuku.isPreV11()).append('\n');
            sb.append("bound: ").append(bound);
        } catch (Throwable t) {
            sb.append("Shizuku not available: ").append(t);
        }
        addLog(sb.toString());
        if (safePing() && safePermission() != 0) {
            try {
                Shizuku.requestPermission(REQUEST_CODE);
                addLog("permission requested");
            } catch (Throwable t) {
                addLog("request failed: " + t);
            }
        } else if (safePing() && !bound) {
            bindService();
        }
    }

    private int safePermission() {
        try {
            return Shizuku.checkSelfPermission();
        } catch (Throwable t) {
            return -1;
        }
    }

    private void showShizukuHelp() {
        new AlertDialog.Builder(this)
                .setTitle("Shizuku is not running")
                .setMessage("Start Shizuku first:\n\n"
                        + "1. open the Shizuku app\n"
                        + "2. use Start via wireless debugging (or pair over USB)\n"
                        + "3. come back here and try again")
                .setPositiveButton("OK", null)
                .show();
    }

    private void prepare() {
        if (!safePing()) {
            showShizukuHelp();
            return;
        }
        if (service == null) {
            bindService();
            toast("Connecting to Shizuku...");
            return;
        }
        toast("Preparing...");
        new Thread(() -> {
            try {
                final String result = service.install(getPackageCodePath());
                addLog(result);
                if (result.startsWith("installed")) {
                    String target = service.run("target");
                    addLog(target.trim());
                    if (!target.contains(TIMER_TARGET)) {
                        addLog("rejected: bundled binary is not built for this kernel");
                    }
                }
                ui.post(() -> {
                    toast(result);
                    refreshDetails();
                });
            } catch (Throwable t) {
                addLog("prepare failed: " + t);
                ui.post(() -> toast("prepare failed: " + t));
            }
        }).start();
    }

    /**
     * Same job as scripts/fetch-timer.ps1, but on the phone: download the
     * upstream prebuilt binary and hand it to the shell-domain service.
     */
    private void downloadTimer() {
        if (downloading) {
            return;
        }
        if (!safePing()) {
            showShizukuHelp();
            return;
        }
        if (safePermission() != 0) {
            try {
                Shizuku.requestPermission(REQUEST_CODE);
                toast("Grant Shizuku permission, then press Download again");
            } catch (Throwable t) {
                addLog("permission request failed: " + t);
                toast("Grant Shizuku permission first");
            }
            return;
        }
        if (service == null) {
            pendingServiceAction = this::downloadTimer;
            bindService();
            toast("Connecting to Shizuku...");
            return;
        }

        final IUserService svc = service;
        downloading = true;
        addLog("downloading exploit from " + TIMER_URL);
        toast("Downloading...");
        new Thread(() -> {
            File file = new File(getCacheDir(), "timer-download");
            try {
                TimerFetcher.Result result = TimerFetcher.download(TIMER_URL, file);
                addLog("downloaded " + result.bytes + " bytes, sha256 " + result.sha256);
                // Publish the per-kernel confs from the APK before the binary:
                // installFd() only replaces /data/local/tmp/timer and leaves
                // the extracted profiles alone.
                addLog(svc.install(getPackageCodePath()));
                String installed;
                try (ParcelFileDescriptor fd = ParcelFileDescriptor.open(
                        file, ParcelFileDescriptor.MODE_READ_ONLY)) {
                    installed = svc.installFd(fd);
                }
                addLog(installed);
                final String message = installed;
                boolean ok = installed.startsWith("installed");
                if (ok) {
                    // Refuse a binary built for another kernel: the timer call
                    // site and cred layout are build-specific, and using the
                    // wrong one corrupts the kernel instead of failing safely.
                    String target = svc.run("target");
                    addLog(target.trim());
                    if (!target.contains(TIMER_TARGET)) {
                        ok = false;
                        addLog("rejected: binary is not built for this kernel");
                    }
                }
                final boolean good = ok;
                ui.post(() -> {
                    downloading = false;
                    toast(good ? "Exploit installed" : message);
                    refreshDetails();
                });
            } catch (Throwable t) {
                addLog("download failed: " + t);
                final String message = "download failed: " + t;
                ui.post(() -> {
                    downloading = false;
                    toast(message);
                });
            } finally {
                //noinspection ResultOfMethodCallIgnored
                file.delete();
            }
        }).start();
    }

    private void toast(String text) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show();
    }

    private void confirmRoot() {
        String message;
        if (AutoRoot.isSamsungMode(this)) {
            message = "Runs the Samsung DEFEX/KDP chain once.\n\n"
                    + "- Requires the diabl0w/KernelSU Samsung build\n"
                    + "- Clears the child's DEFEX creds_fast_hash entry\n"
                    + "- Moves the worker to u:r:init:s0 and late-loads the bundled"
                    + " diabl0w/KernelSU ksud through a private logcat bind mount\n"
                    + "- SELinux is left to ksud's own restore\n"
                    + "- On a failed attempt the process is parked until you reboot\n"
                    + "- Do not use the device while it runs";
        } else {
            message = "Runs CVE-2026-98260 once and keeps a uid=0 shell open.\n\n"
                    + "- On a failed attempt the process is parked until you reboot\n"
                    + "- Root disappears when you reboot\n"
                    + "- Do not use the device while it runs";
        }
        new AlertDialog.Builder(this)
                .setTitle("Get a root shell?")
                .setMessage(message)
                .setPositiveButton("Run", (d, w) -> runRoot())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void runRoot() {
        if (service == null) {
            addLog("bind the service first");
            return;
        }
        new Thread(() -> {
            try {
                boolean samsung = AutoRoot.isSamsungMode(this);
                if (samsung) {
                    String problem = AutoRoot.samsungManagerProblem(this);
                    if (problem != null) {
                        addLog(problem);
                        ui.post(() -> toast(problem));
                        return;
                    }
                }
                service.setSamsungMode(samsung);
                String out = service.openRoot();
                // Only a real uid=0 shell counts; a failed attempt parks the
                // exploit and prints diagnostics that must not look like success.
                rootOpen = out.startsWith("root shell ready");
                addLog(out);
                ui.post(this::applyDetails);
                if (rootOpen && samsung) {
                    /*
                     * The Samsung chain has no separate shell-domain stage:
                     * the same `fake` plant already cleared DEFEX and loaded
                     * ksud, so openRoot() returned the final KernelSU state.
                     */
                    if (out.contains("KernelSU active")) {
                        ksu = "active";
                    }
                    addLog("Samsung chain complete");
                    ui.post(() -> {
                        applyDetails();
                        refreshDetails();
                    });
                } else if (rootOpen && !"active".equals(ksu)) {
                    addLog("root shell ready - loading KernelSU...");
                    runKsu();
                } else if (!rootOpen) {
                    addLog("no root shell: the exploit did not reach uid=0."
                            + " Reboot before retrying.");
                    ui.post(() -> {
                        statusTitle.setText("Root failed");
                        statusSubtitle.setText("exploit did not reach uid=0 - reboot, then retry");
                        styleBadge("!", RED);
                    });
                }
            } catch (Throwable t) {
                addLog("root failed: " + t);
            }
        }).start();
    }

    private void confirmKsu() {
        new AlertDialog.Builder(this)
                .setTitle("Load KernelSU?")
                .setMessage("Late-loads ksud through a fake credential.\n\n"
                        + "- On success su works in u:r:ksu:s0\n"
                        + "- The parent process parks; reboot to clean up\n"
                        + "- Do not use the device while it runs")
                .setPositiveButton("Run", (d, w) -> runKsu())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void runKsu() {
        if (service == null) {
            addLog("bind the service first");
            return;
        }
        if (AutoRoot.isSamsungMode(this)) {
            /*
             * Samsung has one chain, not two: `fake` does the fake cred,
             * DEFEX clear, SELinux and ksud late-load in a single plant.
             * Replanting it here would consume another trigger on a kernel
             * that only tolerates one per boot.
             */
            addLog("Samsung mode: KernelSU loads with the main exploit chain");
            runRoot();
            return;
        }
        new Thread(() -> {
            try {
                addLog(service.runDetached("fake"));
                final long start = System.currentTimeMillis();
                boolean loaded = false;
                String failure = null;
                boolean sawLateLoad = false;
                int lastLen = -1;
                long lastChange = System.currentTimeMillis();
                while (System.currentTimeMillis() - start < 90000) {
                    Thread.sleep(1000);
                    String tail = service.readLog();
                    sawLateLoad |= tail.contains("[ksu] late-load rc=0");
                    if (tail.length() != lastLen) {
                        lastLen = tail.length();
                        lastChange = System.currentTimeMillis();
                    }
                    if (tail.contains("KSU_LOADED")) {
                        loaded = true;
                        break;
                    }
                    if (tail.contains("selinux write failed")) {
                        failure = "the selinux stage missed its race";
                        break;
                    }
                    if (tail.contains("KSU_STALE")) {
                        failure = "an old KernelSU module is still loaded - reboot, then retry";
                        break;
                    }
                    if (tail.contains("[ksu] ksud missing")) {
                        failure = "no supported manager (KernelSU, KernelSU-Next, SukiSU)";
                        break;
                    }
                    if (tail.contains("KSU_MISSING")) {
                        failure = "ksud late-load failed - see the [ksu] log lines";
                        break;
                    }
                    /*
                     * The exploit parent always parks (and says so) once the
                     * stage is done, even when the late-load succeeded - the
                     * line alone means nothing. What matters is whether the
                     * module that is now loaded actually hands out root.
                     */
                    if (tail.contains("parking without reap")) {
                        if (sawLateLoad) {
                            if (service.ksuActive()) {
                                loaded = true;
                            } else {
                                failure = "ksud late-load finished but su is not"
                                        + " available - see the [ksu] log lines";
                            }
                        } else {
                            failure = "the exploit parked before loading ksud";
                        }
                        break;
                    }
                    if (tail.contains("[ksu] late-load rc=0")) {
                        sawLateLoad = true;
                    }
                    /*
                     * SukiSU's loader can take the module and terminate the
                     * stage shell before it prints KSU_LOADED. Once the log
                     * has been quiet for a few seconds after a late-load,
                     * ask the kernel whether root actually works.
                     */
                    if (sawLateLoad
                            && System.currentTimeMillis() - lastChange > 5000) {
                        if (service.ksuActive()) {
                            loaded = true;
                        } else {
                            failure = "ksud late-load finished but su is not"
                                    + " available - see the [ksu] log lines";
                        }
                        break;
                    }
                    final long secs = (System.currentTimeMillis() - start) / 1000;
                    if (secs % 5 == 0) {
                        ui.post(() -> {
                            if (statusSubtitle != null) {
                                statusSubtitle.setText("Loading KernelSU... " + secs + "s");
                            }
                        });
                    }
                }
                if (!loaded && failure == null) {
                    /* Last chance: the stage may have lost its output. */
                    if (service.ksuActive()) {
                        loaded = true;
                    } else {
                        failure = "timed out after 90s";
                    }
                }
                String selinux = "";
                if (loaded) {
                    selinux = service.keepPermissive();
                    addLog("KernelSU loaded: " + selinux);
                    parseInfo(service.info());
                }
                addLog(service.readLog());
                final boolean ok = loaded;
                final String reason = failure;
                final String selinuxState = selinux;
                ui.post(() -> {
                    applyDetails();
                    if (ok) {
                        toast("KernelSU loaded: " + selinuxState);
                        refreshDetails();
                        offerSoftRestart();
                    } else {
                        statusTitle.setText("KernelSU failed");
                        statusSubtitle.setText(reason + " - reboot, then retry");
                        styleBadge("!", RED);
                        toast("KernelSU failed: " + reason);
                        addLog("KernelSU failed: " + reason
                                + " - parked processes remain; reboot to clean up");
                    }
                });
            } catch (Throwable t) {
                addLog("ksu failed: " + t);
            }
        }).start();
    }

    private void stopRoot() {
        if (service == null) {
            return;
        }
        new Thread(() -> {
            try {
                addLog(service.closeRoot());
                rootOpen = false;
                ui.post(this::applyDetails);
            } catch (Throwable t) {
                addLog("stop failed: " + t);
            }
        }).start();
    }

    // ---------------------------------------------------------- auto-root

    private void updateAutoRootUi() {
        if (autoToggle == null) {
            return;
        }
        setToggleState(autoToggle, AutoRoot.isEnabled(this));
        if (samsungToggle != null) {
            setToggleState(samsungToggle, AutoRoot.isSamsungMode(this));
        }
        if (bootToggle != null) {
            setToggleState(bootToggle, AutoRoot.bootUiEnabled(this));
        }
        if (softToggle != null) {
            setToggleState(softToggle, AutoRoot.softRestartEnabled(this));
        }
    }

    /** Pushes the effective mode to the bound shell service. */
    private void applySamsungModeToService() {
        if (service == null) {
            return;
        }
        try {
            service.setSamsungMode(AutoRoot.isSamsungMode(this));
        } catch (Throwable t) {
            addLog("could not set Samsung mode: " + t);
        }
    }

    private void toggleSamsungMode() {
        boolean enabled = !AutoRoot.isSamsungMode(this);
        AutoRoot.setSamsungMode(this, enabled);
        applySamsungModeToService();
        updateAutoRootUi();
        addLog("Samsung mode " + (enabled ? "enabled" : "disabled")
                + (AutoRoot.isSamsungDevice() ? "" : " (device is not Samsung)"));
        if (enabled) {
            String problem = AutoRoot.samsungManagerProblem(this);
            if (problem != null) {
                addLog(problem);
                toast("Samsung mode needs the diabl0w/KernelSU Samsung build");
            }
            if (!AutoRoot.isSamsungDevice()) {
                toast("Samsung mode needs a matching Samsung kernel profile");
            }
        }
    }

    private void useAutoSamsungMode() {
        AutoRoot.useAutoSamsungMode(this);
        applySamsungModeToService();
        updateAutoRootUi();
        addLog("Samsung mode follows automatic detection: "
                + (AutoRoot.isSamsungMode(this) ? "on" : "off"));
    }

    private void toggleSoftRestart() {
        boolean enabled = !AutoRoot.softRestartEnabled(this);
        AutoRoot.setSoftRestartEnabled(this, enabled);
        updateAutoRootUi();
        addLog("auto soft restart " + (enabled ? "enabled" : "disabled"));
        if (!enabled) {
            toast("Android will not restart after root - modules load on the"
                    + " next real reboot");
        }
    }

    private void confirmSoftRestart() {
        if (service == null) {
            toast("bind the service first");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Restart Android?")
                .setMessage("Restarts the Android userspace, like the KernelSU "
                        + "manager's soft reboot.\n\n"
                        + "- Root and the kernel stay up; su keeps working\n"
                        + "- Modules, Zygisk and the root manager's own service "
                        + "start as they would on a real boot\n"
                        + "- Every app closes and the lock screen comes back; "
                        + "it takes about a minute\n"
                        + "- TimerRoot is killed while it runs, so this screen "
                        + "will disappear\n\n"
                        + "Requires KernelSU 3.x for the 'ksud soft-reboot' "
                        + "subcommand.")
                .setPositiveButton("Restart Android", (d, w) -> softRestartNow())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void toggleBootUi() {
        boolean enabled = !AutoRoot.bootUiEnabled(this);
        AutoRoot.setBootUiEnabled(this, enabled);
        updateAutoRootUi();
        addLog("boot status screen " + (enabled ? "enabled" : "disabled"));
        if (enabled) {
            requestNotificationPermission();
            if (!BootStatusActivity.canStartDirectly(this)
                    && !fullScreenAllowed()) {
                toast("Allow overlay or full-screen access, or the screen "
                        + "cannot appear over the lock screen");
            }
        }
    }

    private boolean fullScreenAllowed() {
        if (Build.VERSION.SDK_INT < 34) {
            return true;
        }
        NotificationManager manager = getSystemService(NotificationManager.class);
        try {
            return manager == null || manager.canUseFullScreenIntent();
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Offers the userspace restart after a manual KernelSU load. It is what
     * makes the module's scripts and Zygisk take effect, but it closes every
     * app and takes a minute, so it is never done without asking here. The
     * boot path does it automatically (see AutoRootService).
     */
    private void offerSoftRestart() {
        if (service == null) {
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Restart Android now?")
                .setMessage("KernelSU is loaded, but modules and Zygisk only "
                        + "start after a userspace restart.\n\n"
                        + "This closes every app and shows the lock screen again, "
                        + "like a reboot, but it keeps the kernel running, so root "
                        + "survives and the parked exploit processes stay parked. "
                        + "It takes about a minute.\n\n"
                        + "Skip it if you are only using su on the command line.")
                .setPositiveButton("Restart Android", (d, w) -> softRestartNow())
                .setNegativeButton("Not now", null)
                .show();
    }

    private void softRestartNow() {
        if (service == null) {
            toast("bind the service first");
            return;
        }
        addLog("soft restart: requesting a userspace restart...");
        toast("Restarting Android...");
        new Thread(() -> {
            try {
                final String result = service.softRestart();
                addLog("soft restart: " + result);
            } catch (Throwable t) {
                /*
                 * Expected: the restart kills this process, so the binder call
                 * dies mid-flight. Nothing to report.
                 */
                addLog("soft restart returned: " + t);
            }
        }).start();
    }

    private void requestOverlay() {        if (Settings.canDrawOverlays(this)) {
            toast("Display over other apps is already allowed");
            return;
        }
        try {
            startActivity(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getPackageName())));
        } catch (Throwable t) {
            addLog("overlay settings failed: " + t);
            toast("Could not open the overlay settings");
        }
    }

    private void requestFullScreen() {
        if (Build.VERSION.SDK_INT < 34) {
            toast("Full-screen notifications are always allowed before Android 14");
            return;
        }
        if (fullScreenAllowed()) {
            toast("Full-screen notification access is already allowed");
            return;
        }
        try {
            startActivity(new Intent(
                    Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
                    Uri.parse("package:" + getPackageName())));
        } catch (Throwable t) {
            addLog("full-screen settings failed: " + t);
            toast("Could not open the full-screen notification settings");
        }
    }

    private void previewBootUi() {
        try {
            startActivity(BootStatusActivity.intent(this));
        } catch (Throwable t) {
            addLog("boot screen preview failed: " + t);
            toast("Could not open the boot screen");
        }
    }

    private void pickBootMedia() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES,
                new String[]{"image/*", "video/*"});
        try {
            startActivityForResult(intent, REQUEST_BOOT_MEDIA);
        } catch (Throwable t) {
            addLog("media picker failed: " + t);
            toast("No file picker available");
        }
    }

    private void clearBootMedia() {
        File[] files = AutoRoot.bootUiDir(this)
                .listFiles((dir, name) -> name.startsWith("background."));
        int removed = 0;
        if (files != null) {
            for (File file : files) {
                //noinspection ResultOfMethodCallIgnored
                if (file.delete()) {
                    removed++;
                }
            }
        }
        toast(removed > 0 ? "Boot background cleared" : "No boot background set");
        addLog("boot background cleared (" + removed + " file(s))");
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_BOOT_MEDIA && resultCode == RESULT_OK
                && data != null && data.getData() != null) {
            copyBootMedia(data.getData());
        }
    }

    /**
     * Copies the chosen image or video into device-protected storage. The
     * boot status screen runs before the first unlock, when normal app files
     * (credential-encrypted) are not readable.
     */
    private void copyBootMedia(Uri uri) {
        final String type;
        try {
            type = getContentResolver().getType(uri);
        } catch (Throwable t) {
            toast("Could not read the selected file");
            return;
        }
        final boolean video = type != null && type.startsWith("video/");
        addLog("copying boot background (" + (video ? "video" : "image") + ")...");
        new Thread(() -> {
            File dest = null;
            try {
                File dir = AutoRoot.bootUiDir(this);
                File[] old = dir.listFiles((d, name) -> name.startsWith("background."));
                if (old != null) {
                    for (File file : old) {
                        //noinspection ResultOfMethodCallIgnored
                        file.delete();
                    }
                }
                dest = new File(dir, video ? "background.video"
                        : "background.image0");
                InputStream in = getContentResolver().openInputStream(uri);
                if (in == null) {
                    throw new IllegalStateException("no stream for " + uri);
                }
                try (InputStream source = in;
                     OutputStream out = new FileOutputStream(dest)) {
                    byte[] buffer = new byte[1 << 16];
                    int read;
                    while ((read = source.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                    }
                }
                long size = dest.length();
                final File saved = dest;
                ui.post(() -> {
                    toast("Boot background set");
                    addLog("boot background ready: " + saved.getName()
                            + " (" + (size / 1024) + " KiB)");
                });
            } catch (Throwable t) {
                AutoRoot.log(this, "boot background copy failed: " + t);
                final File failed = dest;
                ui.post(() -> {
                    toast("Could not save the boot background");
                    addLog("boot background copy failed: " + t);
                    if (failed != null) {
                        //noinspection ResultOfMethodCallIgnored
                        failed.delete();
                    }
                });
            }
        }).start();
    }

    private void toggleAutoRoot() {
        boolean enabled = !AutoRoot.isEnabled(this);
        AutoRoot.setEnabled(this, enabled);
        updateAutoRootUi();
        addLog("auto-root " + (enabled ? "enabled" : "disabled"));
        if (enabled) {
            requestNotificationPermission();
            if (!AutoRoot.prefs(this).getBoolean(AutoRoot.KEY_SETUP_DONE, false)) {
                new AlertDialog.Builder(this)
                        .setTitle("One-time setup left")
                        .setMessage("The first root always needs one manual run.\n\n"
                                + "1. Get a root shell (or just press Install channel)\n"
                                + "2. Install channel clears SELinux and pins a "
                                + "persistent localhost ADB port\n"
                                + "3. Authorize TimerRoot's ADB key once (tap Always allow)\n"
                                + "4. Reboot\n\n"
                                + "After that every boot is automatic as soon as the "
                                + "device is unlocked - Shizuku is started early at the "
                                + "lock screen, and the exploit runs once you unlock. "
                                + "Without the channel, auto-root can still work when "
                                + "Shizuku starts on its own over Wi-Fi.")
                        .setPositiveButton("OK", null)
                        .show();
            }
        }
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[]{android.Manifest.permission.POST_NOTIFICATIONS},
                    REQUEST_NOTIFICATIONS);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
                                           int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_NOTIFICATIONS) {
            addLog(grantResults.length > 0 && grantResults[0]
                    == android.content.pm.PackageManager.PERMISSION_GRANTED
                    ? "notification permission granted"
                    : "notification permission denied (auto-root still runs)");
        }
    }

    /**
     * One-time setup for the no-Wi-Fi boot path.
     *
     * A uid-0 shell from the exploit has no capabilities, so it cannot write
     * /data/misc/adb/adb_keys and cannot switch SELinux off through sysfs.
     * The exploit can clear the kernel's enforcing flag itself (its
     * "permissive" mode), and /data/property is owned by root, so the uid-0
     * shell can then append persist.adb.tcp.port to the protobuf that init
     * reads at the next boot.
     *
     * adb_keys is a different matter: it is 0640 system:shell and appending
     * needs CAP_DAC_OVERRIDE. When KernelSU is already loaded, run the whole
     * setup through its su (full uid-0 capabilities) so the key lands without
     * any dialog. Without a module the shell-domain root cannot touch the
     * file; the key then has to be authorized once by the normal ADB dialog
     * and stays in adb_keys afterwards.
     */
    private void installChannel() {
        if (service == null) {
            toast("Bind the service first");
            return;
        }
        final String key = AutoRoot.publicKeyLine(this);
        if (key == null) {
            toast("Could not create the ADB key");
            return;
        }
        final int port = AutoRoot.adbPort(this);
        addLog("installing the auto-root channel (port " + port + ")...");
        new Thread(() -> {
            try {
                String installed = service.install(getPackageCodePath());
                addLog(installed);

                boolean samsung = AutoRoot.isSamsungMode(this);
                if (samsung) {
                    String problem = AutoRoot.samsungManagerProblem(this);
                    if (problem != null) {
                        addLog(problem);
                        ui.post(() -> toast(problem));
                        return;
                    }
                }
                service.setSamsungMode(samsung);

                String info = service.info();
                addLog(info.trim());
                // KernelSU's su gives a full-capability uid 0 (u:r:ksu:s0),
                // unlike the exploit shell (u:r:shell:s0, no capabilities).
                // Use it when it is there: adb_keys needs CAP_DAC_OVERRIDE.
                boolean ksuActive = info.contains("ksu=active");

                // 1. SELinux permissive: property_data_file is only writable
                //    while the kernel's enforcing flag is clear.
                if (samsung) {
                    // The Samsung chain leaves SELinux to ksud's own restore;
                    // the generic "permissive" plant is a second trigger and
                    // is deliberately not used here.
                    addLog("Samsung mode: SELinux is managed by the ksud chain");
                } else if (!info.contains("selinux=Permissive")) {
                    addLog("clearing SELinux through the exploit"
                            + " (this can take a few minutes)...");
                    String out = service.run("permissive");
                    boolean done = out.contains("permissive done");
                    addLog(done ? "permissive ok" : tailText(out));
                    if (!done) {
                        ui.post(() -> {
                            toast("Could not clear SELinux - reboot and retry");
                            addLog("channel install failed before writing the property."
                                    + " A failed plant parks a zombie, so reboot first.");
                        });
                        return;
                    }
                }

                // 2. root: when KernelSU is already loaded, use su instead of
                //    running the exploit again (each plant parks a process).
                //    Otherwise use the shell-domain stage; Samsung runs the
                //    unified fake/DEFEX/KDP chain.
                if (ksuActive) {
                    addLog("KernelSU is active - running the channel setup"
                            + " through su");
                } else {
                    String out = service.openRoot();
                    boolean ready = out.startsWith("root shell ready")
                            || out.contains("root shell already open");
                    rootOpen = ready;
                    addLog(out);
                    if (!ready) {
                        ui.post(() -> {
                            toast("Could not get a root shell - reboot and retry");
                            addLog("channel install failed: no root shell.");
                        });
                        return;
                    }
                }

                // 3. Append one PersistentProperties record:
                //      field 1 (record) { field 1 (name), field 2 (value) }
                String name = "persist.adb.tcp.port";
                String value = String.valueOf(port);
                int recordLen = 2 + name.length() + 2 + value.length();
                String record = String.format("\\%03o\\%03o\\%03o\\%03o",
                        0x0a, recordLen, 0x0a, name.length())
                        + name
                        + String.format("\\%03o\\%03o", 0x12, value.length())
                        + value;
                String command = "F=/data/property/persistent_properties; "
                        + "if grep -aq '" + name + "' \"$F\"; then echo PROP_PRESENT; "
                        + "else printf '" + record + "' >> \"$F\" && echo PROP_WRITTEN; fi; "
                        + "echo size=$(wc -c < \"$F\"); "
                        + "echo records=$(grep -ac '" + name + "' \"$F\"); "
                        + "settings put global adb_allowed_connection_time 0; "
                        + "echo settings=$?; "
                        + "K='" + key + "'; A=/data/misc/adb/adb_keys; "
                        // Presence first, then write. The exploit shell cannot
                        // write this file (0640 system:shell, no capabilities),
                        // so the attempt is silent and reported as locked
                        // instead of leaking a shell "Permission denied".
                        + "if grep -qF \"$K\" \"$A\" 2>/dev/null; then echo KEY_PRESENT; "
                        + "elif echo \"$K\" 2>/dev/null >> \"$A\"; then "
                        + "chown system:shell \"$A\" 2>/dev/null; "
                        + "chmod 0640 \"$A\" 2>/dev/null; echo KEY_WRITTEN; "
                        + "else echo KEY_LOCKED; fi; "
                        + "key_count=$(grep -cF timerroot \"$A\" 2>/dev/null) "
                        + "|| key_count=unreadable; echo key_count=$key_count; "
                        + "appops set com.kpgc.timerroot android:use_full_screen_intent allow; "
                        + "appops set com.kpgc.timerroot android:system_alert_window allow; "
                        + "echo CHANNEL_DONE";
                String result = ksuActive
                        ? service.execSu(command)
                        : service.execRoot(command);
                addLog(result);
                boolean written = result.contains("PROP_WRITTEN")
                        || result.contains("PROP_PRESENT");
                boolean keyReady = result.contains("KEY_PRESENT")
                        || result.contains("KEY_WRITTEN");
                ui.post(() -> {
                    if (written) {
                        AutoRoot.prefs(this).edit()
                                .putBoolean(AutoRoot.KEY_SETUP_DONE, true).apply();
                        if (keyReady) {
                            toast("Channel installed - reboot to test auto-root");
                            addLog("auto-root channel installed: "
                                    + "persist.adb.tcp.port=" + port
                                    + " and the ADB key is authorized"
                                    + " (active after the next boot).");
                        } else {
                            toast("Channel installed - authorize the ADB key once");
                            addLog("auto-root channel installed: "
                                    + "persist.adb.tcp.port=" + port
                                    + " (active after the next boot)."
                                    + " The ADB key could not be written from the"
                                    + " exploit shell; tap \"Always allow\" once"
                                    + " when the ADB prompt appears after the reboot.");
                        }
                    } else {
                        toast("Could not write the persistent property");
                        addLog("channel install failed: " + tailText(result));
                    }
                });
            } catch (Throwable t) {
                addLog("install channel failed: " + t);
                ui.post(() -> toast("Install channel failed"));
            }
        }).start();
    }

    private static String tailText(String text) {
        if (text == null) {
            return "";
        }
        return text.length() <= 800 ? text : text.substring(text.length() - 800);
    }

    private void confirmAutoRootNow() {
        new AlertDialog.Builder(this)
                .setTitle("Run auto-root now?")
                .setMessage("Runs the boot sequence immediately: start Shizuku, bind "
                        + "it, install timer and run the exploit once.\n\n"
                        + "Do not use this if the exploit already ran this boot - "
                        + "each boot gets a single attempt.")
                .setPositiveButton("Run", (d, w) -> startAutoRoot())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void startAutoRoot() {
        Intent intent = new Intent(this, AutoRootService.class)
                .setAction(AutoRootService.ACTION_RUN_NOW);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }
            toast("Auto-root started");
        } catch (Throwable t) {
            addLog("auto-root start failed: " + t);
            toast("Could not start auto-root");
        }
    }

    private void reboot() {
        new AlertDialog.Builder(this)
                .setTitle("Reboot the device?")
                .setMessage("This is the only way to clean up parked processes.")
                .setPositiveButton("Reboot", (d, w) -> {
                    if (service == null) {
                        toast("bind the service first");
                        return;
                    }
                    new Thread(() -> {
                        try {
                            final String result = service.rebootDevice();
                            ui.post(() -> toast(result));
                        } catch (Throwable t) {
                            ui.post(() -> toast("reboot failed: " + t));
                        }
                    }).start();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void run(String label, String args) {
        if (service == null) {
            addLog("bind the service first");
            return;
        }
        new Thread(() -> {
            try {
                addLog("[" + label + "]\n" + service.run(args));
            } catch (Throwable t) {
                addLog("[" + label + "] failed: " + t);
            }
        }).start();
    }

    // ------------------------------------------------------------ plumbing

    private void bindService() {
        try {
            Shizuku.bindUserService(serviceArgs(), connection);
            addLog("binding user service...");
        } catch (Throwable t) {
            addLog("bind failed: " + t);
        }
    }

    private Shizuku.UserServiceArgs serviceArgs() {
        return new Shizuku.UserServiceArgs(
                new ComponentName(getPackageName(), UserService.class.getName()))
                .daemon(false)
                .processNameSuffix("timer")
                .debuggable(false)
                .version(8);
    }

    private void copyLog() {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("TimerRoot", logText.getText()));
                addLog("log copied");
            }
        } catch (Throwable t) {
            addLog("copy failed: " + t);
        }
    }

    private void addLog(String text) {
        String stamp = clock.format(new Date());
        StringBuilder sb = new StringBuilder();
        for (String line : text.split("\n")) {
            sb.append(stamp).append("  ").append(line).append('\n');
        }
        Log.i(TAG, text.replace('\n', ' '));
        ui.post(() -> {
            if (logText != null) {
                logText.append(sb.toString());
            }
            if (logScroll != null) {
                logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
            }
        });
    }
}