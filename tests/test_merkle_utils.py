# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

"""
测试merkle_utils.py中的函数和类
"""
from bytedance.jeddak_secure_channel.merkle_utils import MerkleProof, verify_inclusion


def test_verify_inclusion():
    proof = {'metadata': {'algorithm': 'sha512', 'security': True, 'size': 1}, 'rule': [0], 'subset': [], 'path': ['c3760988735a1743bb2dbbc0cdac4a84c68d80ed3105286e24e112d76b62efcca39844a669f3855cd7ab467e47ff46f871ee7c32c530384e85bfd81f7519247f']}
    base = 'c3760988735a1743bb2dbbc0cdac4a84c68d80ed3105286e24e112d76b62efcca39844a669f3855cd7ab467e47ff46f871ee7c32c530384e85bfd81f7519247f'
    root = 'c3760988735a1743bb2dbbc0cdac4a84c68d80ed3105286e24e112d76b62efcca39844a669f3855cd7ab467e47ff46f871ee7c32c530384e85bfd81f7519247f'

    proof = MerkleProof.deserialize(proof)
    ret = verify_inclusion(bytes.fromhex(base), bytes.fromhex(root), proof)
    print(f"ret={ret}")


def main():
    """
    主函数
    """

    test_verify_inclusion()


if __name__ == "__main__":
    main()
