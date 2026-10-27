import java.util.Properties

plugins {
    id("com.android.application")
}

// Release signing, if android/keystore.properties exists (storeFile,
// storePassword, keyAlias, keyPassword)
val signing = rootProject.file("keystore.properties").takeIf { it.exists() }?.let { file ->
    Properties().apply { file.inputStream().use { load(it) } }
}

android {
    namespace = "com.firaxite.passman"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.firaxite.passman"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
    }

    signingConfigs {
        if (signing != null) {
            create("release") {
                storeFile = rootProject.file(signing.getProperty("storeFile"))
                storePassword = signing.getProperty("storePassword")
                keyAlias = signing.getProperty("keyAlias")
                keyPassword = signing.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    // the web app, built by scripts/build-android.mjs
    sourceSets["main"].assets.directories.add("build/web")
}

dependencies {
    implementation("androidx.webkit:webkit:1.15.0")
}
