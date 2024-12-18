plugins {
    id("frybits-library")
}

kotlin {
    jvm()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(libs.kotlin.serialization)
            }
        }

        val commonTest by getting {
            dependencies {
            }
        }
    }
}
