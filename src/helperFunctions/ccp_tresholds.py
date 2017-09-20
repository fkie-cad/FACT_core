from collections import namedtuple

ProcessValues = namedtuple('ProcessValues', ['slow', 'shigh', 'clow', 'chigh', 'glow', 'ghigh'])
AnalysisResult = namedtuple('AnalysisResult', ['shannon', 'chi', 'gtest'])

ENCRYPTED = {
    '1024': [
        ProcessValues(slow=0.9708, shigh=0.9710, clow=-1, chigh=0.9590, glow=-1, ghigh=0.0357),
        ProcessValues(slow=0.9711, shigh=0.9836, clow=-1, chigh=0.9629, glow=-1, ghigh=0.0357),
        ProcessValues(slow=0.9715, shigh=0.9836, clow=0.9629, chigh=0.9707, glow=-1, ghigh=0.0357),
        ProcessValues(slow=-1, shigh=0.9725, clow=0.9707, chigh=0.9746, glow=-1, ghigh=0.03186),
        ProcessValues(slow=0.9727, shigh=0.9836, clow=0.9707, chigh=0.9746, glow=-1, ghigh=0.0357),
        ProcessValues(slow=-1, shigh=0.9836, clow=0.9747, chigh=3000, glow=-1, ghigh=0.0317)
    ],
    '4096': [
        ProcessValues(slow=-1, shigh=1000, clow=-1, chigh=1000, glow=-1, ghigh=0.031334)
    ],
    '12288': [
        ProcessValues(slow=-1, shigh=100, clow=-1, chigh=500, glow=-1, ghigh=0.32314),
    ]
}

COMPRESSED = {
    '1024': [
        ProcessValues(slow=-1, shigh=0.9707, clow=-1, chigh=0.9590, glow=-1, ghigh=0.0357),
        ProcessValues(slow=-1, shigh=0.9710, clow=0.9590, chigh=0.9629, glow=-1, ghigh=0.0357),
        ProcessValues(slow=-1, shigh=0.9714, clow=0.9629, chigh=0.9707, glow=-1, ghigh=0.0357),
        ProcessValues(slow=-1, shigh=0.9725, clow=0.9629, chigh=0.9746, glow=0.031861, ghigh=0.0357),
        ProcessValues(slow=-1, shigh=0.9836, clow=0.9747, chigh=3000, glow=0.0317, ghigh=0.0357),
        ProcessValues(slow=-1, shigh=0.9836, clow=-1, chigh=3000, glow=0.00001, ghigh=0.0357),
        ProcessValues(slow=0.834875, shigh=300, clow=-1, chigh=0.68557, glow=0.0357, ghigh=0.2606),
        ProcessValues(slow=-1, shigh=0.75117, clow=0.68557, chigh=0.818381, glow=0.0357, ghigh=3000),
        ProcessValues(slow=0.75117, shigh=0.863614, clow=0.68557, chigh=3000, glow=0.0357, ghigh=3000),
    ],
    '4096': [
        ProcessValues(slow=-1, shigh=1000, clow=-1, chigh=1000, glow=0.031335, ghigh=0.032894),
        ProcessValues(slow=0.81297, shigh=1000, clow=-1, chigh=1000, glow=0.032894, ghigh=100),
        ProcessValues(slow=0.78172, shigh=0.81297, clow=0.95655, chigh=1000, glow=0.032894, ghigh=100),
        ProcessValues(slow=-1, shigh=0.78172, clow=0.95655, chigh=1000, glow=0.032894, ghigh=1.323416),
    ],
    '12288': [
        ProcessValues(slow=-1, shigh=100, clow=-1, chigh=500, glow=0.032315, ghigh=0.0328),
        ProcessValues(slow=0.895889, shigh=100, clow=-1, chigh=500, glow=0.0329, ghigh=500),
        ProcessValues(slow=0.824318, shigh=0.895888, clow=-1, chigh=0.995932, glow=0.0329, ghigh=500),
        ProcessValues(slow=0.816443, shigh=0.895888, clow=0.995933, chigh=500, glow=0.0329, ghigh=500),
    ]
}

PLAIN = {
    '1024': [
        ProcessValues(slow=0.9837, shigh=300, clow=-1, chigh=3000, glow=-1, ghigh=0),
        ProcessValues(slow=-1, shigh=0.834876, clow=-1, chigh=0.68557, glow=0.0358, ghigh=0.2606),
        ProcessValues(slow=-1, shigh=300, clow=-1, chigh=0.68557, glow=0.2606, ghigh=3000),
        ProcessValues(slow=-1, shigh=0.75117, clow=0.818381, chigh=3000, glow=0.0358, ghigh=3000),
        ProcessValues(slow=0.863614, shigh=300, clow=0.68557, chigh=3000, glow=0.0358, ghigh=3000), ],
    '4096': [
        ProcessValues(slow=-1, shigh=0.78172, clow=0.95655, chigh=1000, glow=1.323416, ghigh=100),
        ProcessValues(slow=-1, shigh=0.81297, clow=-1, chigh=0.95655, glow=0.032894, ghigh=100)
    ],
    '12288': [
        ProcessValues(slow=-1, shigh=0.816442, clow=-1, chigh=500, glow=0.0329, ghigh=500),
        ProcessValues(slow=-1, shigh=0.824317, clow=-1, chigh=0.995932, glow=0.0329, ghigh=500)
    ]
}


class BlockClass:
    encrypted = 'blue'
    compressed = 'red'
    plain = 'green'
    unknown = 'yellow'


def new_categorization_from_features(block_features, blocksize):
    result = AnalysisResult(shannon=block_features['shannon'], chi=block_features['chi'],
                            gtest=block_features['g-test'])

    if blocksize == 1024:
        if _is_in_class(ENCRYPTED[str(blocksize)], result):
            return BlockClass.encrypted
        if _is_in_class(COMPRESSED[str(blocksize)], result):
            return BlockClass.compressed
        if _is_in_class(PLAIN[str(blocksize)], result):
            return BlockClass.plain
        return BlockClass.unknown
    else:
        if _is_in_class(COMPRESSED[str(blocksize)], result):
            return BlockClass.compressed
        if _is_in_class(ENCRYPTED[str(blocksize)], result):
            return BlockClass.encrypted
        if _is_in_class(PLAIN[str(blocksize)], result):
            return BlockClass.plain
        return BlockClass.unknown


def _is_in_class(class_array, result):
    return any(
        v.slow < result.shannon <= v.shigh and v.clow < result.chi <= v.chigh and v.glow < result.gtest <= v.ghigh
        for v in class_array)
