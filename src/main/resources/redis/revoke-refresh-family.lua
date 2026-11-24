-- Standalone Redis: inspect the user's token index atomically so legacy families
-- without a dedicated family index are covered too. All type checks precede writes.
local function validType(key, expected)
    local actual = redis.call('TYPE', key).ok
    return actual == 'none' or actual == expected
end
if not validType(KEYS[1], 'set') or not validType(KEYS[2], 'string') then
    return redis.error_reply('Refresh family revoke encountered an invalid key type')
end
local ttl = tonumber(ARGV[3])
if not ttl or ttl <= 0 or ttl ~= math.floor(ttl) then
    return redis.error_reply('Refresh family revoke requires a positive TTL')
end
local previousTtl = redis.call('PTTL', KEYS[2])
local persistent = previousTtl == -1
ttl = math.max(ttl, previousTtl)
local targets = {}
for _, hash in ipairs(redis.call('SMEMBERS', KEYS[1])) do
    local hashKey = ARGV[1] .. 'hash:' .. hash
    if not validType(hashKey, 'string') then
        return redis.error_reply('Refresh family hash has an invalid key type')
    end
    local jti = redis.call('GET', hashKey)
    if jti then
        local tokenKey = ARGV[1] .. 'token:' .. jti
        if not validType(tokenKey, 'string') then
            return redis.error_reply('Refresh family metadata has an invalid key type')
        end
        local json = redis.call('GET', tokenKey)
        local ok, meta = false, nil
        if json then ok, meta = pcall(cjson.decode, json) end
        if ok and type(meta) == 'table' and meta.familyId == ARGV[2]
                and meta.userId == tonumber(ARGV[4]) then
            local hashTtl = redis.call('PTTL', hashKey)
            local tokenTtl = redis.call('PTTL', tokenKey)
            if hashTtl == -1 or tokenTtl == -1 then persistent = true end
            ttl = math.max(ttl, hashTtl, tokenTtl)
            targets[#targets + 1] = {hashKey, tokenKey, hash}
        end
    end
end
-- Keep the marker until the longest-lived active descendant expires. Missing TTL
-- is a data anomaly: retain revocation rather than risk reactivating that family.
if persistent then redis.call('SET', KEYS[2], '1')
else redis.call('SET', KEYS[2], '1', 'PX', tostring(ttl)) end
for _, target in ipairs(targets) do
    redis.call('DEL', target[1], target[2])
    redis.call('SREM', KEYS[1], target[3])
end
return #targets
