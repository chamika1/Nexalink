# Android build and testing

## GitHub Actions
Every push to main triggers unit tests and a debug APK build. A successful run uploads an artifact named `nexalink-android-debug` (retained for seven days).

1. Open the repository's **Actions** tab.
2. Select the latest **Android Debug Build** run.
3. Check that all steps passed.
4. Download `nexalink-android-debug` under **Artifacts**.

The APK is a development build and should not be distributed as a production secure remote-assistance app.

## Local development
Open the repository root in Android Studio with JDK 17 and Android SDK 35. The CI workflow uses Gradle 8.9. This repository does not yet include the Gradle wrapper.

Run:
```sh
gradle :android:app:testDebugUnitTest :android:app:assembleDebug
```

## Test pairing

Install the debug APK on two Android devices and follow the [pairing walkthrough](../android/README.md#pair-two-android-devices). Check that each device appears in the other's Devices list after verification and remains listed after restarting the app. Remove a device and confirm it disappears from the local list.
