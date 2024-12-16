plugins {
    id("frybits-library")
}

kotlin {
    jvm()

    sourceSets {
        val jvmMain by getting {
            dependencies {
                implementation(libs.bouncycastle.bcpkix.jdk18on )
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlin.serialization)
            }
        }

        val jvmTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
    }
}
