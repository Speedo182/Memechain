#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <ctime>
#include <unordered_map>
#include <random>
#include <map>
#include <queue>
#include <functional>
#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using namespace boost::multiprecision;

class Block {
public:
    int64_t index;
    int64_t timestamp;
    string previous_hash;
    string hash;
    string data;
    vector<string> shard_id;

    Block(int64_t idx, int64_t ts, string prev_hash, string hsh, string d, vector<string> shard)
        : index(idx), timestamp(ts), previous_hash(prev_hash), hash(hsh), data(d), shard_id(shard) {}

    string calculate_hash() {
        stringstream ss;
        ss << index << timestamp << previous_hash << data;
        return ss.str();
    }

    void mine_block(int difficulty) {
        char target[difficulty + 1];
        for (int i = 0; i < difficulty; i++) {
            target[i] = '0';
        }
        target[difficulty] = '\0';

        string curr_hash = calculate_hash();
        while (curr_hash.substr(0, difficulty) != target) {
            index++;
            timestamp = chrono::system_clock::to_time_t(chrono::system_clock::now());
            curr_hash = calculate_hash();
        }
        hash = curr_hash;
    }
};

class Blockchain {
public:
    vector<Block> chain;
    int difficulty;
    unordered_map<string,vector<Block>> shard_chain;
    map<string,int> off_chain_data;
    cpp_int private_key;
    cpp_int public_key;
    cpp_int n, e;

    Blockchain() {
        difficulty = 4;
        chain.push_back(Block(0, time(0), "0", "0", "Genesis Block", {"0"}));
        for (int i = 0; i < 10; i++) {
            string shard = to_string(i);
            shard_chain[shard] = {};
        }
        private_key = rand();
        public_key = pow(2, private_key);
        n = public_key;
        e = private_key;
    }

        void add_block(string data) {
        int64_t curr_index = chain.size();
        int64_t curr_timestamp = time(0);
        string curr_prev_hash = chain.back().hash;
        vector<string> shard_id;
        mt19937 rng(random_device{}());
        uniform_int_distribution<mt19937::result_type> dist(0, 9);
        for (int i = 0; i < 3; i++) {
            shard_id.push_back(to_string(dist(rng)));
        }
        Block new_block(curr_index, curr_timestamp, curr_prev_hash, "", data, shard_id);
        new_block.mine_block(difficulty);
        for(auto shard: shard_id) {
            shard_chain[shard].push_back(new_block);
        }
        chain.push_back(new_block);
    }

    void add_off_chain_data(string shard, int data) {
        off_chain_data[shard] = data;
    }

    void encrypt_data(string data) {
        cpp_int m = cpp_int(data);
        cpp_int c = powm(m, e, n);
    }

    void decrypt_data(cpp_int data) {
        cpp_int m = powm(data, private_key, n);
    }

    bool is_valid() {
        for (int i = 1; i < chain.size(); i++) {
            Block curr = chain[i];
            Block prev = chain[i - 1];
            if (curr.hash != curr.calculate_hash()) {
                return false;
            }
            if (curr.previous_hash != prev.hash) {
                return false;
            }
        }
        return true;
    }
};
