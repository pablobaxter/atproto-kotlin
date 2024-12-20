/*
 *  Copyright 2024 Pablo Baxter
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * Created by Pablo Baxter (Github: pablobaxter)
 */

package com.frybits.gradle

import com.vanniktech.maven.publish.MavenPublishPlugin
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.apply
import org.gradle.kotlin.dsl.withType
import org.jetbrains.dokka.gradle.DokkaMultiModuleTask
import org.jetbrains.dokka.gradle.DokkaPlugin
import org.jetbrains.dokka.gradle.DokkaTaskPartial
import org.jetbrains.dokka.gradle.GradleExternalDocumentationLinkBuilder
import org.jetbrains.kotlin.gradle.plugin.KotlinMultiplatformPluginWrapper
import org.jetbrains.kotlinx.serialization.gradle.SerializationGradleSubplugin
import java.net.URI

class FrybitsLibraryPlugin : Plugin<Project> {

    override fun apply(target: Project) = target.run {
        apply<KotlinMultiplatformPluginWrapper>()

        apply<SerializationGradleSubplugin>()

        configureCommon()

        configureDokka()
        apply<MavenPublishPlugin>()
    }
}

private fun Project.configureDokka() {
    apply<DokkaPlugin>()
    val mmTask = tasks.findByName("dokkaHtmlMultiModule") as? DokkaMultiModuleTask
    if (mmTask != null) {
        // Disabling for library modules, so the app submodule doesn't publish docs
        mmTask.enabled = false
    }
    tasks.withType<DokkaTaskPartial> {
        dokkaSourceSets.configureEach {
            externalDocumentationLinks.add(
                GradleExternalDocumentationLinkBuilder(this@configureDokka).apply {
                    url.set(URI("https://kotlinlang.org/api/kotlinx.coroutines/").toURL())
                }
            )
        }
    }
}
