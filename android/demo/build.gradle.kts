// A login form in a separate app, for trying (and testing) autofill
plugins {
    id("com.android.application")
}

android {
    namespace = "com.firaxite.passmandemo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.firaxite.passmandemo"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
