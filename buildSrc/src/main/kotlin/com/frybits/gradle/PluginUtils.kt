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

import com.autonomousapps.DependencyAnalysisPlugin
import com.autonomousapps.DependencyAnalysisSubExtension
import org.gradle.api.Project
import org.gradle.kotlin.dsl.apply
import org.gradle.kotlin.dsl.configure
import org.jlleitschuh.gradle.ktlint.KtlintExtension
import org.jlleitschuh.gradle.ktlint.KtlintPlugin

internal fun Project.configureCommon() {
    applyKtlint()
    applyDependencyAnalysis()
}

internal fun Project.applyKtlint() {
    apply<KtlintPlugin>()
    configure<KtlintExtension> {
        version.set("0.48.2")
        outputToConsole.set(true)
        outputColorName.set("RED")
    }
}

internal fun Project.applyDependencyAnalysis() {
    apply<DependencyAnalysisPlugin>()
    configure<DependencyAnalysisSubExtension> {
        issues {
            onAny {
                severity("fail")
            }
        }
    }
}
