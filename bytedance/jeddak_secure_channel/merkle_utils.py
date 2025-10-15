# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

"""
Merkle树相关实现，替代pymerkle
"""

import hashlib
from hmac import compare_digest


SHA2_ALGORITHMS = ['sha224', 'sha256', 'sha384', 'sha512']
SHA3_ALGORITHMS = ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512']
KECCAK_ALGORITHMS = ['keccak_224', 'keccak_256', 'keccak_384', 'keccak_512']


ALGORITHMS = SHA2_ALGORITHMS + SHA3_ALGORITHMS
try:
    import sha3
except ImportError:
    pass
else:
    ALGORITHMS += KECCAK_ALGORITHMS


class InvalidProof(Exception):
    """
    Raised when a Merkle-proof is found to be invalid.
    """
    pass


class MerkleProof:
    def __init__(self, algorithm, security, size, rule, subset, path):
        self.algorithm = algorithm
        self.security = security
        self.size = size
        self.rule = rule
        self.subset = subset
        self.path = path

    @classmethod
    def deserialize(cls, data):
        """
        :param data:
        :type data: dict
        :rtype: MerkleProof
        """
        metadata = data['metadata']
        rule = data['rule']
        subset = data['subset']
        path = [bytes.fromhex(checksum) for checksum in data['path']]

        return cls(**metadata, rule=rule, subset=subset, path=path)


def verify_inclusion(base, root, proof):
    """
    :param base: 声称的叶节点哈希
    :type base: bytes
    :param root: 声称的根节点哈希
    :type root: bytes
    :param proof: 包含证明对象
    :type proof: MerkleProof
    :raises InvalidProof: 如果证明无效
    """
    # 验证base哈希是否与proof路径的第一个元素匹配
    if not compare_digest(proof.path[0], base):
        raise InvalidProof('Base hash does not match')

    # 初始化哈希函数
    algorithm = proof.algorithm
    normalized = algorithm.lower().replace('-', '_')

    # 获取合适的哈希模块
    if normalized in KECCAK_ALGORITHMS:
        import sha3
        module = sha3
    else:
        module = hashlib

    # 确保算法受支持
    if normalized not in ALGORITHMS:
        msg = f'{algorithm} not supported'
        if normalized in KECCAK_ALGORITHMS:
            msg += ': You need to install pysha3'
        raise ValueError(msg)

    hashfunc = getattr(module, algorithm)
    security = proof.security
    prefx01 = b'\x01' if security else b''

    # 执行resolve逻辑，直接计算根哈希
    rule = proof.rule
    path = proof.path

    # 准备路径和规则的配对
    path_with_rule = list(zip(rule, path))

    if not path_with_rule:
        # 空树的情况
        hasher = hashfunc()
        result = hasher.digest()
    else:
        # 从第一个元素开始计算
        bit, result = path_with_rule[0]
        index = 0

        # 遍历路径中的每个元素
        while index < len(path_with_rule) - 1:
            next_bit, digest = path_with_rule[index + 1]

            # 根据bit值决定哈希顺序
            if bit == 0:
                # 当前结果在左，下一个digest在右
                hasher = hashfunc()
                if security:
                    hasher.update(prefx01)
                hasher.update(result)
                hasher.update(digest)
                result = hasher.digest()
            elif bit == 1:
                # 下一个digest在左，当前结果在右
                hasher = hashfunc()
                if security:
                    hasher.update(prefx01)
                hasher.update(digest)
                hasher.update(result)
                result = hasher.digest()
            else:
                raise ValueError('Invalid bit found')

            bit = next_bit
            index += 1

    # 验证计算出的根哈希是否与提供的根哈希匹配
    if not compare_digest(result, root):
        raise InvalidProof('State does not match')

    return True
