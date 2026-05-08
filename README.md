# Nanochain

> 블록체인 학습용으로 만든 미니 PoS 체인. [Commonware](https://github.com/commonwarexyz/monorepo) 스택 기반.

[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Status](https://img.shields.io/badge/status-WIP-yellow.svg)](#로드맵)

---

블록체인의 핵심 컴포넌트(블록·트랜잭션·머클·머ㅁpool·컨센서스·스토리지·네트워크)를 직접 만져보며 이해하기 위한 교육용 프로젝트. Do not use this on production!!!

목표:
- BFT 컨센서스를 commonware로 빠르게 붙여보고 동작 원리 이해

---

## 📚 학습 노트

이 프로젝트를 따라가며 직접 정리한 개념들:

- **머클 트리**: 트랜잭션 N개를 32바이트 루트 1개로 압축. O(log N) 포함 증명. → `tx_root` 헤더 필드로 블록 무결성 확보
- **Simplex 컨센서스**: 단순한 BFT 합의 알고리즘. commonware-consensus가 구현 제공
  - 추후 바뀔 수 있음
- **Mempool nonce 정렬**: 같은 발신자의 트랜잭션 순서 보장 (ETH식)
- **상태 모델**: UTXO vs Account-based — 나노체인은 Account-based (`HashMap<address, balance>`)
  - 추후 추상화 레이어로 UTXO도 한번 가능하게

---

> ⚠️ **Warning!**: 본 프로젝트는 교육 목적으로만 작성되었으며, 실제 자산을 다루는 용도로 사용하면 안됩니다.
