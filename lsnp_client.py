#!/usr/bin/env python3
"""
Local Social Networking Protocol (LSNP) Client Implementation
CSNETWK Machine Problem - RFC XXXX Implementation

This implementation supports all LSNP message types and features:
- User discovery and presence
- Messaging (POST, DM, FOLLOW, UNFOLLOW, LIKE)
- File transfer with chunking
- Group management
- Tic Tac Toe gameplay
- Token validation and scoping
- Profile pictures and avatars
"""

import socket
import threading
import time
import json
import base64
import hashlib
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import ipaddress
import random

class LSNPClient:
    def __init__(self, username: str, display_name: str, verbose: bool = False):
        self.username = username
        self.display_name = display_name
        self.verbose = verbose
        self.status = "Online"
        
        # Network configuration
        self.port = 50999
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Get local IP
        self.local_ip = self._get_local_ip()
        self.user_id = f"{username}@{self.local_ip}"
        
        # Get broadcast address
        self.broadcast_addr = self._get_broadcast_address()
        
        # State management
        self.peers: Dict[str, Dict] = {}  # user_id -> peer info
        self.posts: List[Dict] = []  # All posts received
        self.dms: List[Dict] = []  # Direct messages
        self.groups: Dict[str, Dict] = {}  # group_id -> group info
        self.games: Dict[str, Dict] = {}  # game_id -> game state
        self.files: Dict[str, Dict] = {}  # file_id -> file info
        self.following: Set[str] = set()  # Users we follow
        self.followers: Set[str] = set()  # Users following us
        
        # Token and security
        self.tokens: Dict[str, Dict] = {}  # Our issued tokens
        self.revoked_tokens: Set[str] = set()  # Revoked token hashes
        
        # Avatar support
        self.avatar_data: Optional[str] = None
        self.avatar_type: Optional[str] = None
        
        # Threading
        self.running = True
        self.listen_thread = None
        self.ping_thread = None
        
        # Message tracking
        self.message_ids: Set[str] = set()  # For duplicate detection
        self.pending_acks: Dict[str, Dict] = {}  # message_id -> retry info
        
    def _get_local_ip(self) -> str:
        """Get the local IP address"""
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _get_broadcast_address(self) -> str:
        """Calculate broadcast address for the local network"""
        try:
            # Simple approach: assume /24 network
            ip_parts = self.local_ip.split('.')
            ip_parts[-1] = '255'
            return '.'.join(ip_parts)
        except:
            return "255.255.255.255"
    
    def _generate_message_id(self) -> str:
        """Generate a random 64-bit message ID in hex format"""
        return f"{random.getrandbits(64):016x}"
    
    def _generate_token(self, scope: str, ttl: int = 3600) -> str:
        """Generate a token with format: user_id|timestamp+ttl|scope"""
        timestamp = int(time.time())
        return f"{self.user_id}|{timestamp + ttl}|{scope}"
    
    def _validate_token(self, token: str, expected_scope: str, sender_ip: str) -> bool:
        """Validate token format, expiration, scope, and revocation"""
        try:
            # Check if token is revoked
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if token_hash in self.revoked_tokens:
                if self.verbose:
                    print(f"[TOKEN] Rejected revoked token: {token}")
                return False
            
            # Parse token
            parts = token.split('|')
            if len(parts) != 3:
                if self.verbose:
                    print(f"[TOKEN] Invalid format: {token}")
                return False
            
            user_id, expiry_str, scope = parts
            
            # Validate scope
            if scope != expected_scope:
                if self.verbose:
                    print(f"[TOKEN] Scope mismatch. Expected: {expected_scope}, Got: {scope}")
                return False
            
            # Validate expiration
            expiry = int(expiry_str)
            if time.time() > expiry:
                if self.verbose:
                    print(f"[TOKEN] Expired token: {token}")
                return False
            
            # Validate user IP matches sender IP (basic spoofing protection)
            token_ip = user_id.split('@')[1]
            if token_ip != sender_ip:
                if self.verbose:
                    print(f"[TOKEN] IP mismatch. Token IP: {token_ip}, Sender IP: {sender_ip}")
                return False
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"[TOKEN] Validation error: {e}")
            return False
    
    def _parse_message(self, data: str) -> Optional[Dict]:
        """Parse LSNP message format"""
        try:
            lines = data.strip().split('\n')
            if not lines:
                return None
            
            message = {}
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    message[key.strip()] = value.strip()
            
            return message if message else None
        except Exception as e:
            if self.verbose:
                print(f"[PARSE] Error parsing message: {e}")
            return None
    
    def _format_message(self, message: Dict) -> str:
        """Format message in LSNP key-value format"""
        lines = []
        for key, value in message.items():
            lines.append(f"{key}: {value}")
        lines.append("")  # Blank line terminator
        return '\n'.join(lines)
    
    def _send_message(self, message: Dict, target_ip: str = None, expect_ack: bool = False):
        """Send LSNP message"""
        formatted = self._format_message(message)
        
        if target_ip:
            # Unicast
            addr = (target_ip, self.port)
        else:
            # Broadcast
            addr = (self.broadcast_addr, self.port)
        
        try:
            self.socket.sendto(formatted.encode('utf-8'), addr)
            
            if self.verbose:
                print(f"[SEND >] To {addr[0]}:{addr[1]}")
                print(formatted)
            
            # Handle ACK expectation
            if expect_ack and 'MESSAGE_ID' in message:
                self.pending_acks[message['MESSAGE_ID']] = {
                    'message': message,
                    'target_ip': target_ip,
                    'sent_time': time.time(),
                    'retries': 0
                }
                
        except Exception as e:
            if self.verbose:
                print(f"[SEND] Error: {e}")
    
    def _send_ack(self, message_id: str):
        """Send ACK message"""
        ack_msg = {
            'TYPE': 'ACK',
            'MESSAGE_ID': message_id,
            'STATUS': 'RECEIVED'
        }
        self._send_message(ack_msg)
    
    def start(self):
        """Start the LSNP client"""
        try:
            self.socket.bind(('', self.port))
            print(f"[CLIENT] Started on {self.local_ip}:{self.port}")
            print(f"[CLIENT] User ID: {self.user_id}")
            print(f"[CLIENT] Broadcast: {self.broadcast_addr}")
            
            # Start listening thread
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()
            
            # Start ping thread
            self.ping_thread = threading.Thread(target=self._ping_loop, daemon=True)
            self.ping_thread.start()
            
            # Start retry thread
            self.retry_thread = threading.Thread(target=self._retry_loop, daemon=True)
            self.retry_thread.start()
            
            # Send initial profile
            self.send_profile()
            
        except Exception as e:
            print(f"[CLIENT] Failed to start: {e}")
            return False
        
        return True
    
    def stop(self):
        """Stop the client"""
        self.running = False
        if self.socket:
            self.socket.close()
    
    def _listen_loop(self):
        """Main listening loop"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                sender_ip = addr[0]
                
                # Don't process our own messages
                if sender_ip == self.local_ip:
                    continue
                
                message_str = data.decode('utf-8')
                message = self._parse_message(message_str)
                
                if message:
                    if self.verbose:
                        print(f"[RECV <] From {sender_ip}:{addr[1]}")
                        print(message_str)
                    
                    self._handle_message(message, sender_ip)
                    
            except Exception as e:
                if self.running and self.verbose:
                    print(f"[LISTEN] Error: {e}")
    
    def _ping_loop(self):
        """Send periodic PING messages"""
        last_profile = 0
        while self.running:
            current_time = time.time()
            
            # Send PROFILE every 300 seconds, PING otherwise
            if current_time - last_profile >= 300:
                self.send_profile()
                last_profile = current_time
            else:
                self.send_ping()
            
            # Wait 300 seconds (5 minutes)
            for _ in range(300):
                if not self.running:
                    break
                time.sleep(1)
    
    def _retry_loop(self):
        """Handle message retries for ACK expectations"""
        while self.running:
            current_time = time.time()
            to_remove = []
            
            for msg_id, info in self.pending_acks.items():
                # Check if we should retry (2 second timeout)
                if current_time - info['sent_time'] >= 2:
                    if info['retries'] < 3:
                        # Retry
                        info['retries'] += 1
                        info['sent_time'] = current_time
                        
                        if self.verbose:
                            print(f"[RETRY] Message {msg_id}, attempt {info['retries']}")
                        
                        self._send_message(info['message'], info['target_ip'])
                    else:
                        # Give up
                        if self.verbose:
                            print(f"[RETRY] Giving up on message {msg_id}")
                        to_remove.append(msg_id)
            
            for msg_id in to_remove:
                del self.pending_acks[msg_id]
            
            time.sleep(1)
    
    def _handle_message(self, message: Dict, sender_ip: str):
        """Handle received LSNP message"""
        msg_type = message.get('TYPE')
        
        # Handle ACK messages
        if msg_type == 'ACK':
            msg_id = message.get('MESSAGE_ID')
            if msg_id in self.pending_acks:
                if self.verbose:
                    print(f"[ACK] Received for message {msg_id}")
                del self.pending_acks[msg_id]
            return
        
        # Send ACK for messages that need it
        if 'MESSAGE_ID' in message and msg_type in ['DM', 'TICTACTOE_INVITE', 'TICTACTOE_MOVE']:
            self._send_ack(message['MESSAGE_ID'])
        
        # Check for duplicate messages
        if 'MESSAGE_ID' in message:
            if message['MESSAGE_ID'] in self.message_ids:
                if self.verbose:
                    print(f"[DUPLICATE] Ignoring duplicate message {message['MESSAGE_ID']}")
                return
            self.message_ids.add(message['MESSAGE_ID'])
        
        # Route to specific handlers
        handler_map = {
            'PROFILE': self._handle_profile,
            'POST': self._handle_post,
            'DM': self._handle_dm,
            'PING': self._handle_ping,
            'FOLLOW': self._handle_follow,
            'UNFOLLOW': self._handle_unfollow,
            'LIKE': self._handle_like,
            'FILE_OFFER': self._handle_file_offer,
            'FILE_CHUNK': self._handle_file_chunk,
            'FILE_RECEIVED': self._handle_file_received,
            'REVOKE': self._handle_revoke,
            'TICTACTOE_INVITE': self._handle_tictactoe_invite,
            'TICTACTOE_MOVE': self._handle_tictactoe_move,
            'TICTACTOE_RESULT': self._handle_tictactoe_result,
            'GROUP_CREATE': self._handle_group_create,
            'GROUP_UPDATE': self._handle_group_update,
            'GROUP_MESSAGE': self._handle_group_message,
        }
        
        handler = handler_map.get(msg_type)
        if handler:
            handler(message, sender_ip)
        else:
            if self.verbose:
                print(f"[HANDLER] Unknown message type: {msg_type}")
    
    def _handle_profile(self, message: Dict, sender_ip: str):
        """Handle PROFILE message"""
        user_id = message.get('USER_ID')
        if not user_id:
            return
        
        # Verify IP matches
        if user_id.split('@')[1] != sender_ip:
            if self.verbose:
                print(f"[PROFILE] IP mismatch for {user_id}")
            return
        
        # Update peer info
        self.peers[user_id] = {
            'display_name': message.get('DISPLAY_NAME', user_id),
            'status': message.get('STATUS', ''),
            'last_seen': time.time(),
            'avatar_type': message.get('AVATAR_TYPE'),
            'avatar_data': message.get('AVATAR_DATA')
        }
        
        if not self.verbose:
            print(f"[PROFILE] {message.get('DISPLAY_NAME', user_id)}: {message.get('STATUS', '')}")
    
    def _handle_post(self, message: Dict, sender_ip: str):
        """Handle POST message"""
        user_id = message.get('USER_ID')
        token = message.get('TOKEN')
        
        if not self._validate_token(token, 'broadcast', sender_ip):
            return
        
        # Check if we follow this user
        if user_id not in self.following:
            return
        
        # Add to posts
        post = {
            'user_id': user_id,
            'content': message.get('CONTENT', ''),
            'timestamp': int(message.get('TIMESTAMP', time.time())),
            'message_id': message.get('MESSAGE_ID'),
            'ttl': int(message.get('TTL', 3600))
        }
        self.posts.append(post)
        
        if not self.verbose:
            display_name = self.peers.get(user_id, {}).get('display_name', user_id)
            print(f"[POST] {display_name}: {post['content']}")
    
    def _handle_dm(self, message: Dict, sender_ip: str):
        """Handle DM message"""
        from_user = message.get('FROM')
        to_user = message.get('TO')
        token = message.get('TOKEN')
        
        # Check if message is for us
        if to_user != self.user_id:
            return
        
        if not self._validate_token(token, 'chat', sender_ip):
            return
        
        # Add to DMs
        dm = {
            'from': from_user,
            'to': to_user,
            'content': message.get('CONTENT', ''),
            'timestamp': int(message.get('TIMESTAMP', time.time())),
            'message_id': message.get('MESSAGE_ID')
        }
        self.dms.append(dm)
        
        if not self.verbose:
            display_name = self.peers.get(from_user, {}).get('display_name', from_user)
            print(f"[DM] {display_name}: {dm['content']}")
    
    def _handle_ping(self, message: Dict, sender_ip: str):
        """Handle PING message"""
        user_id = message.get('USER_ID')
        if user_id and user_id in self.peers:
            self.peers[user_id]['last_seen'] = time.time()
        
        # Respond with PROFILE
        self.send_profile()
    
    def _handle_follow(self, message: Dict, sender_ip: str):
        """Handle FOLLOW message"""
        from_user = message.get('FROM')
        to_user = message.get('TO')
        token = message.get('TOKEN')
        
        if to_user != self.user_id:
            return
        
        if not self._validate_token(token, 'follow', sender_ip):
            return
        
        self.followers.add(from_user)
        
        if not self.verbose:
            display_name = self.peers.get(from_user, {}).get('display_name', from_user)
            print(f"[FOLLOW] User {display_name} has followed you")
    
    def _handle_unfollow(self, message: Dict, sender_ip: str):
        """Handle UNFOLLOW message"""
        from_user = message.get('FROM')
        to_user = message.get('TO')
        token = message.get('TOKEN')
        
        if to_user != self.user_id:
            return
        
        if not self._validate_token(token, 'follow', sender_ip):
            return
        
        self.followers.discard(from_user)
        
        if not self.verbose:
            display_name = self.peers.get(from_user, {}).get('display_name', from_user)
            print(f"[UNFOLLOW] User {display_name} has unfollowed you")
    
    def _handle_like(self, message: Dict, sender_ip: str):
        """Handle LIKE message"""
        from_user = message.get('FROM')
        to_user = message.get('TO')
        post_timestamp = message.get('POST_TIMESTAMP')
        action = message.get('ACTION')
        token = message.get('TOKEN')
        
        if to_user != self.user_id:
            return
        
        if not self._validate_token(token, 'broadcast', sender_ip):
            return
        
        # Find the post
        target_post = None
        for post in self.posts:
            if post['timestamp'] == int(post_timestamp) and post['user_id'] == self.user_id:
                target_post = post
                break
        
        if target_post and not self.verbose:
            display_name = self.peers.get(from_user, {}).get('display_name', from_user)
            print(f"[LIKE] {display_name} {action.lower()}d your post: {target_post['content']}")
    
    def _handle_file_offer(self, message: Dict, sender_ip: str):
        """Handle FILE_OFFER message"""
        from_user = message.get('FROM')
        to_user = message.get('TO')
        filename = message.get('FILENAME')
        filesize = int(message.get('FILESIZE', 0))
        filetype = message.get('FILETYPE')
        file_id = message.get('FILEID')
        token = message.get('TOKEN')
        
        if to_user != self.user_id:
            return
        
        if not self._validate_token(token, 'file', sender_ip):
            return
        
        # Store file offer info
        self.files[file_id] = {
            'from': from_user,
            'filename': filename,
            'filesize': filesize,
            'filetype': filetype,
            'chunks': {},
            'total_chunks': 0,
            'received_chunks': 0
        }
        
        if not self.verbose:
            display_name = self.peers.get(from_user, {}).get('display_name', from_user)
            print(f"[FILE] User {display_name} is sending you a file '{filename}' ({filesize} bytes). Do you accept?")
    
    def _handle_file_chunk(self, message: Dict, sender_ip: str):
        """Handle FILE_CHUNK message"""
        from_user = message.get('FROM')
        to_user = message.get('TO')
        file_id = message.get('FILEID')
        chunk_index = int(message.get('CHUNK_INDEX', 0))
        total_chunks = int(message.get('TOTAL_CHUNKS', 0))
        data = message.get('DATA', '')
        token = message.get('TOKEN')
        
        if to_user != self.user_id:
            return
        
        if not self._validate_token(token, 'file', sender_ip):
            return
        
        if file_id not in self.files:
            return
        
        # Store chunk
        file_info = self.files[file_id]
        file_info['chunks'][chunk_index] = data
        file_info['total_chunks'] = total_chunks
        file_info['received_chunks'] = len(file_info['chunks'])
        
        # Check if file is complete
        if file_info['received_chunks'] == total_chunks:
            self._reconstruct_file(file_id)
    
    def _handle_file_received(self, message: Dict, sender_ip: str):
        """Handle FILE_RECEIVED message"""
        # This is just a notification that file was received
        pass
    
    def _handle_revoke(self, message: Dict, sender_ip: str):
        """Handle REVOKE message"""
        token = message.get('TOKEN')
        if token:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            self.revoked_tokens.add(token_hash)
            if self.verbose:
                print(f"[REVOKE] Token revoked: {token}")
    
    def _handle_tictactoe_invite(self, message: Dict, sender_ip: str):
        """Handle TICTACTOE_INVITE message"""
        from_user = message.get('FROM')
        to_user = message.get('TO')
        game_id = message.get('GAMEID')
        symbol = message.get('SYMBOL')
        token = message.get('TOKEN')
        
        if to_user != self.user_id:
            return
        
        if not self._validate_token(token, 'game', sender_ip):
            return
        
        # Create game state
        self.games[game_id] = {
            'player1': from_user,
            'player2': self.user_id,
            'symbol1': symbol,
            'symbol2': 'O' if symbol == 'X' else 'X',
            'board': [' '] * 9,
            'turn': 1,
            'current_player': from_user if symbol == 'X' else self.user_id
        }
        
        if not self.verbose:
            display_name = self.peers.get(from_user, {}).get('display_name', from_user)
            print(f"[GAME] {display_name} is inviting you to play tic-tac-toe (Game {game_id})")
    
    def _handle_tictactoe_move(self, message: Dict, sender_ip: str):
        """Handle TICTACTOE_MOVE message"""
        from_user = message.get('FROM')
        to_user = message.get('TO')
        game_id = message.get('GAMEID')
        position = int(message.get('POSITION', 0))
        symbol = message.get('SYMBOL')
        turn = int(message.get('TURN', 0))
        token = message.get('TOKEN')
        
        if to_user != self.user_id:
            return
        
        if not self._validate_token(token, 'game', sender_ip):
            return
        
        if game_id not in self.games:
            return
        
        game = self.games[game_id]
        
        # Validate move
        if game['board'][position] != ' ':
            return
        
        if turn != game['turn']:
            return
        
        # Make move
        game['board'][position] = symbol
        game['turn'] += 1
        
        # Switch current player
        if game['current_player'] == game['player1']:
            game['current_player'] = game['player2']
        else:
            game['current_player'] = game['player1']
        
        if not self.verbose:
            self._print_board(game_id)
    
    def _handle_tictactoe_result(self, message: Dict, sender_ip: str):
        """Handle TICTACTOE_RESULT message"""
        game_id = message.get('GAMEID')
        result = message.get('RESULT')
        symbol = message.get('SYMBOL')
        winning_line = message.get('WINNING_LINE')
        
        if game_id not in self.games:
            return
        
        if not self.verbose:
            self._print_board(game_id)
            print(f"[GAME] Game {game_id} ended: {result} for {symbol}")
            if winning_line:
                print(f"[GAME] Winning line: {winning_line}")
    
    def _handle_group_create(self, message: Dict, sender_ip: str):
        """Handle GROUP_CREATE message"""
        from_user = message.get('FROM')
        group_id = message.get('GROUP_ID')
        group_name = message.get('GROUP_NAME')
        members = message.get('MEMBERS', '').split(',')
        token = message.get('TOKEN')
        
        if not self._validate_token(token, 'group', sender_ip):
            return
        
        # Check if we're in the group
        if self.user_id not in members:
            return
        
        # Create group
        self.groups[group_id] = {
            'name': group_name,
            'creator': from_user,
            'members': set(members)
        }
        
        if not self.verbose:
            print(f"[GROUP] You've been added to '{group_name}' (ID: {group_id})")
    
    def _handle_group_update(self, message: Dict, sender_ip: str):
        """Handle GROUP_UPDATE message"""
        from_user = message.get('FROM')
        group_id = message.get('GROUP_ID')
        add_users = message.get('ADD', '').split(',') if message.get('ADD') else []
        remove_users = message.get('REMOVE', '').split(',') if message.get('REMOVE') else []
        token = message.get('TOKEN')
        
        if not self._validate_token(token, 'group', sender_ip):
            return
        
        if group_id not in self.groups:
            return
        
        group = self.groups[group_id]
        
        # Update membership
        for user in add_users:
            if user:
                group['members'].add(user)
        
        for user in remove_users:
            if user:
                group['members'].discard(user)
        
        # Check if we were removed
        if self.user_id not in group['members']:
            del self.groups[group_id]
            if not self.verbose:
                print(f"[GROUP] You were removed from '{group['name']}'")
        else:
            if not self.verbose:
                print(f"[GROUP] The group '{group['name']}' member list was updated")
    
    def _handle_group_message(self, message: Dict, sender_ip: str):
        """Handle GROUP_MESSAGE message"""
        from_user = message.get('FROM')
        group_id = message.get('GROUP_ID')
        content = message.get('CONTENT', '')
        token = message.get('TOKEN')
        
        if not self._validate_token(token, 'group', sender_ip):
            return
        
        if group_id not in self.groups:
            return
        
        if not self.verbose:
            display_name = self.peers.get(from_user, {}).get('display_name', from_user)
            group_name = self.groups[group_id]['name']
            print(f"[GROUP:{group_name}] {display_name}: {content}")
    
    def _reconstruct_file(self, file_id: str):
        """Reconstruct file from chunks"""
        if file_id not in self.files:
            return
        
        file_info = self.files[file_id]
        
        # Sort chunks by index and combine
        chunks = []
        for i in range(file_info['total_chunks']):
            if i in file_info['chunks']:
                chunks.append(base64.b64decode(file_info['chunks'][i]))
        
        # Write file
        filename = f"received_{file_info['filename']}"
        with open(filename, 'wb') as f:
            for chunk in chunks:
                f.write(chunk)
        
        # Send FILE_RECEIVED
        msg = {
            'TYPE': 'FILE_RECEIVED',
            'FROM': self.user_id,
            'TO': file_info['from'],
            'FILEID': file_id,
            'STATUS': 'COMPLETE',
            'TIMESTAMP': str(int(time.time()))
        }
        target_ip = file_info['from'].split('@')[1]
        self._send_message(msg, target_ip)
        
        if not self.verbose:
            print(f"[FILE] File transfer of '{file_info['filename']}' is complete")
    
    def _print_board(self, game_id: str):
        """Print tic-tac-toe board"""
        if game_id not in self.games:
            return
        
        game = self.games[game_id]
        board = game['board']
        
        print(f"\nGame {game_id}:")
        print(f" {board[0]} | {board[1]} | {board[2]} ")
        print("-----------")
        print(f" {board[3]} | {board[4]} | {board[5]} ")
        print("-----------")
        print(f" {board[6]} | {board[7]} | {board[8]} ")
        
        current_player_name = self.peers.get(game['current_player'], {}).get('display_name', game['current_player'])
        print(f"Current turn: {current_player_name}")
    
    def _check_win(self, board: List[str], symbol: str) -> Optional[str]:
        """Check if symbol has won and return winning line"""
        winning_combinations = [
            [0, 1, 2], [3, 4, 5], [6, 7, 8],  # Rows
            [0, 3, 6], [1, 4, 7], [2, 5, 8],  # Columns
            [0, 4, 8], [2, 4, 6]              # Diagonals
        ]
        
        for combo in winning_combinations:
            if all(board[i] == symbol for i in combo):
                return ','.join(map(str, combo))
        
        return None
    
    # Public API methods
    def send_profile(self):
        """Send PROFILE message"""
        message = {
            'TYPE': 'PROFILE',
            'USER_ID': self.user_id,
            'DISPLAY_NAME': self.display_name,
            'STATUS': self.status
        }
        
        if self.avatar_data and self.avatar_type:
            message['AVATAR_TYPE'] = self.avatar_type
            message['AVATAR_ENCODING'] = 'base64'
            message['AVATAR_DATA'] = self.avatar_data
        
        self._send_message(message)
    
    def send_ping(self):
        """Send PING message"""
        message = {
            'TYPE': 'PING',
            'USER_ID': self.user_id
        }
        self._send_message(message)
    
    def send_post(self, content: str, ttl: int = 3600):
        """Send POST message"""
        message = {
            'TYPE': 'POST',
            'USER_ID': self.user_id,
            'CONTENT': content,
            'TTL': str(ttl),
            'MESSAGE_ID': self._generate_message_id(),
            'TIMESTAMP': str(int(time.time())),
            'TOKEN': self._generate_token('broadcast', ttl)
        }
        self._send_message(message)
        print(f"[SENT] Post: {content}")
    
    def send_dm(self, target_user: str, content: str):
        """Send DM message"""
        if target_user not in self.peers:
            print(f"[ERROR] User {target_user} not found")
            return
        
        target_ip = target_user.split('@')[1]
        message = {
            'TYPE': 'DM',
            'FROM': self.user_id,
            'TO': target_user,
            'CONTENT': content,
            'TIMESTAMP': str(int(time.time())),
            'MESSAGE_ID': self._generate_message_id(),
            'TOKEN': self._generate_token('chat')
        }
        self._send_message(message, target_ip, expect_ack=True)
        print(f"[SENT] DM to {target_user}: {content}")
    
    def follow_user(self, target_user: str):
        """Follow a user"""
        if target_user not in self.peers:
            print(f"[ERROR] User {target_user} not found")
            return
        
        target_ip = target_user.split('@')[1]
        message = {
            'TYPE': 'FOLLOW',
            'MESSAGE_ID': self._generate_message_id(),
            'FROM': self.user_id,
            'TO': target_user,
            'TIMESTAMP': str(int(time.time())),
            'TOKEN': self._generate_token('follow')
        }
        self._send_message(message, target_ip)
        self.following.add(target_user)
        print(f"[SENT] Following {target_user}")
    
    def unfollow_user(self, target_user: str):
        """Unfollow a user"""
        if target_user not in self.peers:
            print(f"[ERROR] User {target_user} not found")
            return
        
        target_ip = target_user.split('@')[1]
        message = {
            'TYPE': 'UNFOLLOW',
            'MESSAGE_ID': self._generate_message_id(),
            'FROM': self.user_id,
            'TO': target_user,
            'TIMESTAMP': str(int(time.time())),
            'TOKEN': self._generate_token('follow')
        }
        self._send_message(message, target_ip)
        self.following.discard(target_user)
        print(f"[SENT] Unfollowed {target_user}")
    
    def like_post(self, target_user: str, post_timestamp: int):
        """Like a post"""
        if target_user not in self.peers:
            print(f"[ERROR] User {target_user} not found")
            return
        
        target_ip = target_user.split('@')[1]
        message = {
            'TYPE': 'LIKE',
            'FROM': self.user_id,
            'TO': target_user,
            'POST_TIMESTAMP': str(post_timestamp),
            'ACTION': 'LIKE',
            'TIMESTAMP': str(int(time.time())),
            'TOKEN': self._generate_token('broadcast')
        }
        self._send_message(message, target_ip)
        print(f"[SENT] Liked post from {target_user}")
    
    def send_file(self, target_user: str, filename: str):
        """Send file to user"""
        if target_user not in self.peers:
            print(f"[ERROR] User {target_user} not found")
            return
        
        if not os.path.exists(filename):
            print(f"[ERROR] File {filename} not found")
            return
        
        # Read file
        with open(filename, 'rb') as f:
            file_data = f.read()
        
        file_id = self._generate_message_id()
        filesize = len(file_data)
        filetype = 'application/octet-stream'  # Default MIME type
        
        # Send file offer
        target_ip = target_user.split('@')[1]
        offer_msg = {
            'TYPE': 'FILE_OFFER',
            'FROM': self.user_id,
            'TO': target_user,
            'FILENAME': os.path.basename(filename),
            'FILESIZE': str(filesize),
            'FILETYPE': filetype,
            'FILEID': file_id,
            'DESCRIPTION': f'File: {os.path.basename(filename)}',
            'TIMESTAMP': str(int(time.time())),
            'TOKEN': self._generate_token('file')
        }
        self._send_message(offer_msg, target_ip)
        
        # Send file chunks (max 1024 bytes per chunk)
        chunk_size = 1024
        total_chunks = (filesize + chunk_size - 1) // chunk_size
        
        for i in range(total_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, filesize)
            chunk_data = file_data[start:end]
            
            chunk_msg = {
                'TYPE': 'FILE_CHUNK',
                'FROM': self.user_id,
                'TO': target_user,
                'FILEID': file_id,
                'CHUNK_INDEX': str(i),
                'TOTAL_CHUNKS': str(total_chunks),
                'CHUNK_SIZE': str(len(chunk_data)),
                'TOKEN': self._generate_token('file'),
                'DATA': base64.b64encode(chunk_data).decode('utf-8')
            }
            self._send_message(chunk_msg, target_ip)
        
        print(f"[SENT] File {filename} to {target_user} ({total_chunks} chunks)")
    
    def create_group(self, group_id: str, group_name: str, members: List[str]):
        """Create a new group"""
        all_members = [self.user_id] + members
        members_str = ','.join(all_members)
        
        message = {
            'TYPE': 'GROUP_CREATE',
            'FROM': self.user_id,
            'GROUP_ID': group_id,
            'GROUP_NAME': group_name,
            'MEMBERS': members_str,
            'TIMESTAMP': str(int(time.time())),
            'TOKEN': self._generate_token('group')
        }
        
        # Send to all members
        for member in members:
            if member != self.user_id and member in self.peers:
                target_ip = member.split('@')[1]
                self._send_message(message, target_ip)
        
        # Add to our groups
        self.groups[group_id] = {
            'name': group_name,
            'creator': self.user_id,
            'members': set(all_members)
        }
        
        print(f"[SENT] Created group '{group_name}' with {len(all_members)} members")
    
    def send_group_message(self, group_id: str, content: str):
        """Send message to group"""
        if group_id not in self.groups:
            print(f"[ERROR] Group {group_id} not found")
            return
        
        group = self.groups[group_id]
        message = {
            'TYPE': 'GROUP_MESSAGE',
            'FROM': self.user_id,
            'GROUP_ID': group_id,
            'CONTENT': content,
            'TIMESTAMP': str(int(time.time())),
            'TOKEN': self._generate_token('group')
        }
        
        # Send to all members except ourselves
        for member in group['members']:
            if member != self.user_id and member in self.peers:
                target_ip = member.split('@')[1]
                self._send_message(message, target_ip)
        
        print(f"[SENT] Group message to '{group['name']}': {content}")
    
    def invite_tictactoe(self, target_user: str):
        """Invite user to tic-tac-toe game"""
        if target_user not in self.peers:
            print(f"[ERROR] User {target_user} not found")
            return
        
        game_id = f"g{random.randint(0, 255)}"
        target_ip = target_user.split('@')[1]
        
        message = {
            'TYPE': 'TICTACTOE_INVITE',
            'FROM': self.user_id,
            'TO': target_user,
            'GAMEID': game_id,
            'MESSAGE_ID': self._generate_message_id(),
            'SYMBOL': 'X',
            'TIMESTAMP': str(int(time.time())),
            'TOKEN': self._generate_token('game')
        }
        
        # Create game state
        self.games[game_id] = {
            'player1': self.user_id,
            'player2': target_user,
            'symbol1': 'X',
            'symbol2': 'O',
            'board': [' '] * 9,
            'turn': 1,
            'current_player': self.user_id
        }
        
        self._send_message(message, target_ip, expect_ack=True)
        print(f"[SENT] Tic-tac-toe invitation to {target_user} (Game {game_id})")
    
    def make_tictactoe_move(self, game_id: str, position: int):
        """Make a tic-tac-toe move"""
        if game_id not in self.games:
            print(f"[ERROR] Game {game_id} not found")
            return
        
        game = self.games[game_id]
        
        # Check if it's our turn
        if game['current_player'] != self.user_id:
            print("[ERROR] Not your turn")
            return
        
        # Check if position is valid
        if position < 0 or position > 8 or game['board'][position] != ' ':
            print("[ERROR] Invalid position")
            return
        
        # Determine our symbol and opponent
        if game['player1'] == self.user_id:
            our_symbol = game['symbol1']
            opponent = game['player2']
        else:
            our_symbol = game['symbol2']
            opponent = game['player1']
        
        # Make move locally
        game['board'][position] = our_symbol
        game['turn'] += 1
        game['current_player'] = opponent
        
        # Send move
        target_ip = opponent.split('@')[1]
        message = {
            'TYPE': 'TICTACTOE_MOVE',
            'FROM': self.user_id,
            'TO': opponent,
            'GAMEID': game_id,
            'MESSAGE_ID': self._generate_message_id(),
            'POSITION': str(position),
            'SYMBOL': our_symbol,
            'TURN': str(game['turn'] - 1),
            'TOKEN': self._generate_token('game')
        }
        
        self._send_message(message, target_ip, expect_ack=True)
        self._print_board(game_id)
        
        # Check for win
        winning_line = self._check_win(game['board'], our_symbol)
        if winning_line:
            result_msg = {
                'TYPE': 'TICTACTOE_RESULT',
                'FROM': self.user_id,
                'TO': opponent,
                'GAMEID': game_id,
                'MESSAGE_ID': self._generate_message_id(),
                'RESULT': 'WIN',
                'SYMBOL': our_symbol,
                'WINNING_LINE': winning_line,
                'TIMESTAMP': str(int(time.time()))
            }
            self._send_message(result_msg, target_ip)
            print(f"[GAME] You won game {game_id}!")
    
    def set_avatar(self, image_path: str):
        """Set profile avatar from image file"""
        if not os.path.exists(image_path):
            print(f"[ERROR] Image file {image_path} not found")
            return
        
        # Read and encode image
        with open(image_path, 'rb') as f:
            image_data = f.read()
        
        # Check size (under 20KB)
        if len(image_data) > 20 * 1024:
            print("[ERROR] Image too large (must be under 20KB)")
            return
        
        # Determine MIME type based on extension
        ext = os.path.splitext(image_path)[1].lower()
        mime_types = {
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif'
        }
        
        self.avatar_type = mime_types.get(ext, 'image/png')
        self.avatar_data = base64.b64encode(image_data).decode('utf-8')
        
        print(f"[AVATAR] Set avatar from {image_path}")
        self.send_profile()
    
    def set_status(self, status: str):
        """Set status message"""
        self.status = status
        self.send_profile()
        print(f"[STATUS] Changed to: {status}")
    
    # Display methods
    def show_peers(self):
        """Show known peers"""
        print("\n=== Known Peers ===")
        if not self.peers:
            print("No peers discovered yet")
            return
        
        for user_id, info in self.peers.items():
            status = f"({info['status']})" if info['status'] else ""
            last_seen = time.time() - info['last_seen']
            print(f"{info['display_name']} [{user_id}] {status} (seen {int(last_seen)}s ago)")
    
    def show_posts(self):
        """Show recent posts"""
        print("\n=== Recent Posts ===")
        if not self.posts:
            print("No posts yet")
            return
        
        # Show last 10 posts
        for post in self.posts[-10:]:
            user_info = self.peers.get(post['user_id'], {})
            display_name = user_info.get('display_name', post['user_id'])
            timestamp = datetime.fromtimestamp(post['timestamp']).strftime('%H:%M:%S')
            print(f"[{timestamp}] {display_name}: {post['content']}")
    
    def show_dms(self):
        """Show direct messages"""
        print("\n=== Direct Messages ===")
        if not self.dms:
            print("No DMs yet")
            return
        
        # Show last 10 DMs
        for dm in self.dms[-10:]:
            from_info = self.peers.get(dm['from'], {})
            from_name = from_info.get('display_name', dm['from'])
            timestamp = datetime.fromtimestamp(dm['timestamp']).strftime('%H:%M:%S')
            print(f"[{timestamp}] {from_name}: {dm['content']}")
    
    def show_groups(self):
        """Show groups"""
        print("\n=== Groups ===")
        if not self.groups:
            print("No groups yet")
            return
        
        for group_id, group in self.groups.items():
            members = [self.peers.get(m, {}).get('display_name', m) for m in group['members']]
            print(f"{group['name']} [{group_id}]: {', '.join(members)}")
    
    def show_games(self):
        """Show active games"""
        print("\n=== Active Games ===")
        if not self.games:
            print("No active games")
            return
        
        for game_id, game in self.games.items():
            p1_name = self.peers.get(game['player1'], {}).get('display_name', game['player1'])
            p2_name = self.peers.get(game['player2'], {}).get('display_name', game['player2'])
            current_name = self.peers.get(game['current_player'], {}).get('display_name', game['current_player'])
            print(f"Game {game_id}: {p1_name} vs {p2_name} (Turn: {current_name})")


def main():
    parser = argparse.ArgumentParser(description='LSNP Client')
    parser.add_argument('username', help='Username for this client')
    parser.add_argument('-n', '--name', help='Display name', default=None)
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('--status', help='Initial status message', default='Online')
    
    args = parser.parse_args()
    
    display_name = args.name or args.username
    client = LSNPClient(args.username, display_name, args.verbose)
    client.status = args.status
    
    if not client.start():
        return 1
    
    print(f"\nLSNP Client started. Type 'help' for commands.\n")
    
    try:
        while True:
            try:
                cmd = input(f"{client.display_name}> ").strip()
                if not cmd:
                    continue
                
                parts = cmd.split()
                command = parts[0].lower()
                
                if command == 'help':
                    print("""
Available commands:
  help                    - Show this help
  peers                   - Show known peers
  posts                   - Show recent posts
  dms                     - Show direct messages
  groups                  - Show groups
  games                   - Show active games
  
  post <message>          - Send a public post
  dm <user_id> <message>  - Send direct message
  follow <user_id>        - Follow a user
  unfollow <user_id>      - Unfollow a user
  like <user_id> <timestamp> - Like a post
  
  sendfile <user_id> <filename> - Send file
  avatar <image_path>     - Set avatar image
  status <message>        - Set status message
  
  creategroup <id> <name> <member1> [member2...] - Create group
  groupmsg <group_id> <message> - Send group message
  
  ttt <user_id>           - Invite to tic-tac-toe
  move <game_id> <position> - Make game move (0-8)
  
  verbose                 - Toggle verbose mode
  quit                    - Exit
                    """)
                
                elif command == 'quit' or command == 'exit':
                    break
                
                elif command == 'peers':
                    client.show_peers()
                
                elif command == 'posts':
                    client.show_posts()
                
                elif command == 'dms':
                    client.show_dms()
                
                elif command == 'groups':
                    client.show_groups()
                
                elif command == 'games':
                    client.show_games()
                
                elif command == 'post' and len(parts) > 1:
                    message = ' '.join(parts[1:])
                    client.send_post(message)
                
                elif command == 'dm' and len(parts) > 2:
                    user_id = parts[1]
                    message = ' '.join(parts[2:])
                    client.send_dm(user_id, message)
                
                elif command == 'follow' and len(parts) == 2:
                    client.follow_user(parts[1])
                
                elif command == 'unfollow' and len(parts) == 2:
                    client.unfollow_user(parts[1])
                
                elif command == 'like' and len(parts) == 3:
                    user_id = parts[1]
                    timestamp = int(parts[2])
                    client.like_post(user_id, timestamp)
                
                elif command == 'sendfile' and len(parts) == 3:
                    user_id = parts[1]
                    filename = parts[2]
                    client.send_file(user_id, filename)
                
                elif command == 'avatar' and len(parts) == 2:
                    client.set_avatar(parts[1])
                
                elif command == 'status' and len(parts) > 1:
                    status = ' '.join(parts[1:])
                    client.set_status(status)
                
                elif command == 'creategroup' and len(parts) >= 3:
                    group_id = parts[1]
                    group_name = parts[2]
                    members = parts[3:] if len(parts) > 3 else []
                    client.create_group(group_id, group_name, members)
                
                elif command == 'groupmsg' and len(parts) > 2:
                    group_id = parts[1]
                    message = ' '.join(parts[2:])
                    client.send_group_message(group_id, message)
                
                elif command == 'ttt' and len(parts) == 2:
                    client.invite_tictactoe(parts[1])
                
                elif command == 'move' and len(parts) == 3:
                    game_id = parts[1]
                    position = int(parts[2])
                    client.make_tictactoe_move(game_id, position)
                
                elif command == 'verbose':
                    client.verbose = not client.verbose
                    print(f"Verbose mode: {'ON' if client.verbose else 'OFF'}")
                
                else:
                    print("Unknown command. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[ERROR] {e}")
    
    finally:
        print("\nShutting down...")
        client.stop()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())