local types = {'string', 'string', 'set', 'string', 'string'}
for i, expected in ipairs(types) do
    local actual = redis.call('TYPE', KEYS[i]).ok
    if actual ~= 'none' and actual ~= expected then
        return redis.error_reply('Refresh token save encountered an invalid key type')
    end
end
local ttl = tonumber(ARGV[4])
if not ttl or ttl <= 0 or ttl ~= math.floor(ttl) then
    return redis.error_reply('Refresh token save requires a positive TTL')
end
if redis.call('EXISTS', KEYS[4]) ~= 0
        or (redis.call('GET', KEYS[5]) or '0') ~= ARGV[5] then
    return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[4])
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[4])
redis.call('SADD', KEYS[3], ARGV[3])
return 1
