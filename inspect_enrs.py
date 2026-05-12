#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

KNOWN_FORK_HASH_LABELS = {
    '9f3d2254': 'ethereum-mainnet',
    '07c9462e': 'ethereum-mainnet',
    'c376cf8b': 'ethereum-mainnet',
    'fc64ec04': 'ethereum-mainnet',
    'f0afd0e3': 'ethereum-mainnet',
    'cba2a1c0': 'ethereum-mainnet',
    'e029e991': 'ethereum-mainnet',
    '88cf81d9': 'ethereum-sepolia',
    '268956b6': 'ethereum-sepolia',
    'fe3366e7': 'ethereum-sepolia',
    'ed88b5fd': 'ethereum-sepolia',
    'e2ae4999': 'ethereum-sepolia',
    'dfbd9bed': 'ethereum-holesky',
    '9bc6cb31': 'ethereum-holesky',
    'c61a6098': 'ethereum-holesky',
    'bef71d30': 'ethereum-hoodi',
    '0929e24e': 'ethereum-hoodi',
    '23aa1351': 'ethereum-hoodi',
    '808e16a3': 'bnb-smart-chain',
    '4d518ce1': 'bnb-smart-chain',
    '098d24ac': 'bnb-smart-chain',
    '3f2e9ae4': 'bnb-smart-chain',
    'ef54c1e1': 'bnb-smart-chain-testnet',
    'f0bf43da': 'bnb-smart-chain-testnet',
    '22d523b2': 'polygon-mainnet',
    '0e07e722': 'polygon-mainnet',
    '8b7e4175': 'polygon-amoy',
    'be06a477': 'polygon-amoy',
    '62cf6b79': 'base-mainnet',
    '67da0260': 'base-mainnet',
    'd85c2524': 'base-sepolia',
}


def decode_urlsafe_base64(value: str) -> bytes:
    padding = '=' * ( ( 4 - len(value) % 4 ) % 4 )
    return base64.urlsafe_b64decode(value + padding)


def read_rlp_item(data: bytes, offset: int):
    if offset >= len(data):
        raise ValueError('unexpected end of data')
    prefix = data[offset]
    if prefix <= 0x7F:
        return False, bytes([prefix]), offset + 1
    if prefix <= 0xB7:
        length = prefix - 0x80
        start = offset + 1
        end = start + length
        return False, data[start:end], end
    if prefix <= 0xBF:
        length_of_length = prefix - 0xB7
        start = offset + 1
        end = start + length_of_length
        length = int.from_bytes(data[start:end], 'big')
        payload_start = end
        payload_end = payload_start + length
        return False, data[payload_start:payload_end], payload_end
    if prefix <= 0xF7:
        length = prefix - 0xC0
        start = offset + 1
        end = start + length
        return True, data[start:end], end
    length_of_length = prefix - 0xF7
    start = offset + 1
    end = start + length_of_length
    length = int.from_bytes(data[start:end], 'big')
    payload_start = end
    payload_end = payload_start + length
    return True, data[payload_start:payload_end], payload_end


def decode_list(data: bytes):
    is_list, payload, end = read_rlp_item(data, 0)
    if not is_list or end != len(data):
        raise ValueError('payload is not a single RLP list')
    items = []
    offset = 0
    while offset < len(payload):
        child_is_list, child_payload, offset = read_rlp_item(payload, offset)
        items.append((child_is_list, child_payload))
    return items


def parse_enr(record: str):
    if not record.startswith('enr:'):
        return None
    payload = decode_urlsafe_base64(record[4:])
    items = decode_list(payload)
    if len(items) < 2:
        return None

    seq_is_list, seq_payload = items[0]
    sig_is_list, sig_payload = items[1]
    if seq_is_list or sig_is_list:
        return None

    result = {
        'seq': int.from_bytes(seq_payload, 'big') if seq_payload else 0,
        'signature': sig_payload.hex(),
        'keys': {},
        'recordKeccak256': hashlib.sha3_256(payload).hexdigest(),
    }

    idx = 2
    while idx + 1 < len(items):
        key_is_list, key_payload = items[idx]
        val_is_list, val_payload = items[idx + 1]
        if key_is_list:
            idx += 2
            continue
        key = key_payload.decode('utf-8', errors='replace')
        result['keys'][key] = {
            'hex': val_payload.hex(),
            'utf8': val_payload.decode('utf-8', errors='replace') if not val_is_list else None,
            'uint': int.from_bytes(val_payload, 'big') if ( not val_is_list and len(val_payload) <= 8 ) else None,
            'length': len(val_payload),
            'isList': val_is_list,
        }
        idx += 2
    return result


def extract_fork_id(blob_hex: str):
    blob = bytes.fromhex(blob_hex)
    try:
        items = decode_list(blob)
    except Exception:
        return None
    if len(items) < 2 or items[0][0] or items[1][0]:
        return None
    fork_hash = items[0][1].hex()
    fork_next = int.from_bytes(items[1][1], 'big') if items[1][1] else 0
    return {'forkHash': fork_hash, 'forkNext': fork_next}


def iter_records(all_json_path: Path):
    payload = json.loads(all_json_path.read_text())
    for node_id, record in payload.items():
        enr = record.get('record', '')
        if not enr.startswith('enr:'):
            continue
        yield node_id, record, enr


def print_key_summary(all_json_path: Path):
    key_counts = Counter()
    decoded_count = 0
    for _, _, enr in iter_records(all_json_path):
        decoded = parse_enr(enr)
        if decoded is None:
            continue
        decoded_count += 1
        for key in decoded['keys']:
            key_counts[key] += 1

    print(json.dumps({
        'decodedRecords': decoded_count,
        'uniqueKeyCount': len(key_counts),
        'keys': dict(sorted(key_counts.items(), key=lambda item: (-item[1], item[0]))),
    }, indent=2))


def load_chain_map(config_path: Path):
    payload = json.loads(config_path.read_text())
    chain_map = {}
    for chain in payload.get('chains', []):
        name = chain.get('name')
        if not name:
            continue
        if chain.get('enrField'):
            chain_map.setdefault('enrField', {})[chain['enrField']] = name
        for fork_hash in chain.get('forkHashes', []):
            chain_map.setdefault('forkHash', {})[fork_hash.lower()] = name
        if chain.get('network'):
            chain_map.setdefault('network', {})[chain['network']] = name
    return chain_map


def identify_chain(decoded: dict, chain_map: dict):
    keys = decoded.get('keys', {})
    for enr_field, name in chain_map.get('enrField', {}).items():
        if enr_field in keys:
            return name

    for fork_key in ('eth', 'opel'):
        fork_id = keys.get(fork_key, {}).get('forkId')
        if not fork_id:
            continue
        fork_hash = fork_id.get('forkHash', '').lower()
        if fork_hash in chain_map.get('forkHash', {}):
            return chain_map['forkHash'][fork_hash]
        if fork_hash in KNOWN_FORK_HASH_LABELS:
            return KNOWN_FORK_HASH_LABELS[fork_hash]
    return None


def print_fork_summary(all_json_path: Path, config_path: Path):
    chain_map = load_chain_map(config_path)
    fork_counts = Counter()
    chain_counts = Counter()

    for _, _, enr in iter_records(all_json_path):
        decoded = parse_enr(enr)
        if decoded is None:
            continue

        for fork_key in ('eth', 'opel'):
            if fork_key in decoded['keys']:
                fork = extract_fork_id(decoded['keys'][fork_key]['hex'])
                if fork is not None:
                    decoded['keys'][fork_key]['forkId'] = fork

        chain_name = identify_chain(decoded, chain_map) or 'unknown'
        chain_counts[chain_name] += 1

        for fork_key in ('eth', 'opel'):
            fork_id = decoded['keys'].get(fork_key, {}).get('forkId')
            if not fork_id:
                continue
            label = f"{chain_name}:{fork_key}:{fork_id['forkHash']}:{fork_id['forkNext']}"
            fork_counts[label] += 1

    print(json.dumps({
        'chainCounts': dict(sorted(chain_counts.items(), key=lambda item: (-item[1], item[0]))),
        'forkIds': dict(sorted(fork_counts.items(), key=lambda item: (-item[1], item[0]))),
    }, indent=2))


def print_unknown_fork_details(all_json_path: Path, config_path: Path, limit: int):
    chain_map = load_chain_map(config_path)
    samples = defaultdict(list)
    counts = Counter()

    for node_id, record, enr in iter_records(all_json_path):
        decoded = parse_enr(enr)
        if decoded is None:
            continue

        for fork_key in ('eth', 'opel'):
            if fork_key in decoded['keys']:
                fork = extract_fork_id(decoded['keys'][fork_key]['hex'])
                if fork is not None:
                    decoded['keys'][fork_key]['forkId'] = fork

        chain_name = identify_chain(decoded, chain_map) or 'unknown'
        if chain_name != 'unknown':
            continue

        unknown_keys = sorted(decoded['keys'].keys())
        for fork_key in ('eth', 'opel'):
            fork_id = decoded['keys'].get(fork_key, {}).get('forkId')
            if not fork_id:
                continue
            label = f"{fork_key}:{fork_id['forkHash']}:{fork_id['forkNext']}"
            counts[label] += 1
            if len(samples[label]) >= 3:
                continue
            samples[label].append({
                'nodeId': node_id,
                'score': record.get('score'),
                'lastResponse': record.get('lastResponse'),
                'keys': unknown_keys,
                'forkKey': fork_key,
                'forkId': fork_id,
                'enr': enr,
            })

    result = []
    for label, count in counts.most_common(limit):
        result.append({
            'label': label,
            'count': count,
            'samples': samples[label],
        })
    print(json.dumps(result, indent=2))


def print_unknown_fork_list(all_json_path: Path, config_path: Path):
    chain_map = load_chain_map(config_path)
    counts = Counter()

    for _, _, enr in iter_records(all_json_path):
        decoded = parse_enr(enr)
        if decoded is None:
            continue

        for fork_key in ('eth', 'opel'):
            if fork_key in decoded['keys']:
                fork = extract_fork_id(decoded['keys'][fork_key]['hex'])
                if fork is not None:
                    decoded['keys'][fork_key]['forkId'] = fork

        chain_name = identify_chain(decoded, chain_map) or 'unknown'
        if chain_name != 'unknown':
            continue

        for fork_key in ('eth', 'opel'):
            fork_id = decoded['keys'].get(fork_key, {}).get('forkId')
            if not fork_id:
                continue
            label = f"{fork_key}:{fork_id['forkHash']}:{fork_id['forkNext']}"
            counts[label] += 1

    for label, count in counts.most_common():
        print(f"{count}\t{label}")


def print_base_all_summary(base_all_path: Path):
    payload = json.loads(base_all_path.read_text())
    fork_key_counts = Counter()
    fork_id_counts = Counter()
    opstack_counts = Counter()
    attnets_counts = Counter()
    source_counts = Counter()

    for node in payload.get('nodes', []):
        if node.get('forkKey'):
            fork_key_counts[str(node['forkKey'])] += 1
        if node.get('forkId'):
            label = f"{node.get('forkKey', 'unknown')}:{node['forkId']}:{node.get('forkNext', '')}"
            fork_id_counts[label] += 1
        if node.get('opstackChainId') is not None:
            opstack_counts[str(node['opstackChainId'])] += 1
        if node.get('attnets'):
            attnets_counts[str(node['attnets'])] += 1
        if node.get('source'):
            source_counts[str(node['source'])] += 1

    print(json.dumps({
        'network': payload.get('network'),
        'generated': payload.get('generated'),
        'nodeCount': len(payload.get('nodes', [])),
        'sources': dict(sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))),
        'forkKeys': dict(sorted(fork_key_counts.items(), key=lambda item: (-item[1], item[0]))),
        'forkIds': dict(sorted(fork_id_counts.items(), key=lambda item: (-item[1], item[0]))),
        'opstackChainIds': dict(sorted(opstack_counts.items(), key=lambda item: (-item[1], item[0]))),
        'attnets': dict(sorted(attnets_counts.items(), key=lambda item: (-item[1], item[0]))),
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(description='Inspect ENRs from all.json')
    parser.add_argument('--input', default='all.json', help='path to all.json')
    parser.add_argument('--config', default='chains_config.json', help='path to chains_config.json')
    parser.add_argument('--contains-key', help='only print records containing this ENR key')
    parser.add_argument('--contains-text', help='only print records whose raw enr contains this text')
    parser.add_argument('--limit', type=int, default=20, help='maximum number of matches to print')
    parser.add_argument('--list-keys', action='store_true', help='print all observed ENR keys and their counts')
    parser.add_argument('--list-fork-ids', action='store_true', help='print fork ids grouped by inferred chain name')
    parser.add_argument('--unknown-forks', action='store_true', help='print top unknown fork ids with sample ENRs and observed keys')
    parser.add_argument('--unknown-fork-list', action='store_true', help='print unknown fork ids sorted by count')
    parser.add_argument('--base-all-summary', help='print a summary of fork/opstack/source data from base-all.json')
    args = parser.parse_args()

    if args.base_all_summary:
        print_base_all_summary(Path(args.base_all_summary))
        return

    all_json_path = Path(args.input)
    if args.list_keys:
        print_key_summary(all_json_path)
        return
    if args.list_fork_ids:
        print_fork_summary(all_json_path, Path(args.config))
        return
    if args.unknown_forks:
        print_unknown_fork_details(all_json_path, Path(args.config), args.limit)
        return
    if args.unknown_fork_list:
        print_unknown_fork_list(all_json_path, Path(args.config))
        return

    printed = 0
    for node_id, record, enr in iter_records(all_json_path):
        if args.contains_text and args.contains_text not in enr:
            continue
        decoded = parse_enr(enr)
        if decoded is None:
            continue
        if args.contains_key and args.contains_key not in decoded['keys']:
            continue

        for fork_key in ('eth', 'opel'):
            if fork_key in decoded['keys']:
                fork = extract_fork_id(decoded['keys'][fork_key]['hex'])
                if fork is not None:
                    decoded['keys'][fork_key]['forkId'] = fork

        output = {
            'nodeId': node_id,
            'score': record.get('score'),
            'lastResponse': record.get('lastResponse'),
            'decoded': decoded,
        }
        print(json.dumps(output, indent=2))
        printed += 1
        if printed >= args.limit:
            break

    if printed == 0:
        print('No matching ENRs found.')


if __name__ == '__main__':
    main()
