from plugins.analysis.architecture_detection.internal.kconfig.arm import construct_result as construct_result_arm
from plugins.analysis.architecture_detection.internal.kconfig.mips import construct_result as construct_result_mips


def construct_result(file_object):
    result = {}
    kconfig_str = file_object.processed_analysis.get('kernel_config', {}).get('kernel_config')

    if kconfig_str is None:
        return {}

    result.update(construct_result_arm(kconfig_str))
    result.update(construct_result_mips(kconfig_str))

    return result
