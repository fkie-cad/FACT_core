def get_unmatched_dependencies(fo_list, dependency_list):
    missing_dependencies = []
    for dependency in dependency_list:
        for fo in fo_list:
            if dependency not in fo.processed_analysis:
                missing_dependencies.append(dependency)
    return missing_dependencies
