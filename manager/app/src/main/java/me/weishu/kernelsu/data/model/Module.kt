package me.weishu.kernelsu.data.model

import androidx.compose.runtime.Immutable

@Immutable
data class Module(
    val id: String,
    val name: String,
    val author: String,
    val version: String,
    val versionCode: Int,
    val description: String,
    val enabled: Boolean,
    val update: Boolean,
    val remove: Boolean,
    val updateJson: String,
    val hasWebUi: Boolean,
    val hasActionScript: Boolean,
    val metamodule: Boolean,
    val actionIconPath: String?,
    val webUiIconPath: String?,
    /** "live" or "once" when the installed release is audited for Apply now. */
    val liveApply: String? = null,
    /** True when the installed version code matches the audited release. */
    val liveApplyDefault: Boolean = false,
    /** Effective checkbox state, from the per-module preference. */
    val liveApplyEnabled: Boolean = false,
    /** A one-shot module that is still attached to its target process. */
    val liveApplyApplied: Boolean = false,
    val liveApplyReason: String? = null,
    val deprecatedBy: String? = null,
    val replaces: List<String> = emptyList(),
)
