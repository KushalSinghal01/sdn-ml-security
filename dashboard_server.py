from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

data = {
    'attacks': [],
    'blocked_ips': [],
    'total_attacks': 0,
    'attack_types': {'SYN': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0},
    'network_status': 'SAFE',
    'pending_unblocks': [],
    'reported_ips': set()
}

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'attacks': data['attacks'],
        'blocked_ips': data['blocked_ips'],
        'total_attacks': data['total_attacks'],
        'attack_types': data['attack_types'],
        'network_status': data['network_status'],
        'pending_unblocks': data['pending_unblocks']
    })

@app.route('/api/attack', methods=['POST'])
def report_attack():
    attack = request.json
    src_ip = attack.get('src', '')

    # Duplicate check
    if src_ip in data['reported_ips']:
        return jsonify({'success': True, 'duplicate': True})

    data['reported_ips'].add(src_ip)
    attack['time'] = datetime.now().strftime('%H:%M:%S')
    data['attacks'].insert(0, attack)
    data['total_attacks'] += 1

    # Attack type count — short key extract
    atype = attack.get('type', 'SYN FLOOD')
    short_key = atype.split(' ')[0]
    if short_key in data['attack_types']:
        data['attack_types'][short_key] += 1

    # Blocked IPs mein add karo
    already = any(b['ip'] == src_ip for b in data['blocked_ips'])
    if not already:
        data['blocked_ips'].append({
            'ip': src_ip,
            'time': attack['time'],
            'reason': attack.get('reason', ''),
            'type': atype,
            'status': 'blocked'
        })

    data['network_status'] = 'UNDER ATTACK'
    return jsonify({'success': True})

@app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    ip = request.json.get('ip')
    for entry in data['blocked_ips']:
        if entry['ip'] == ip:
            entry['status'] = 'unblocked'
    data['reported_ips'].discard(ip)
    if ip not in data['pending_unblocks']:
        data['pending_unblocks'].append(ip)
    if not any(e['status'] == 'blocked' for e in data['blocked_ips']):
        data['network_status'] = 'SAFE'
    return jsonify({'success': True})

@app.route('/api/pending_unblocks', methods=['GET'])
def get_pending_unblocks():
    return jsonify({'pending': data['pending_unblocks']})

@app.route('/api/confirm_unblock', methods=['POST'])
def confirm_unblock():
    ip = request.json.get('ip')
    if ip in data['pending_unblocks']:
        data['pending_unblocks'].remove(ip)
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
