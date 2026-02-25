package params

import "time"

const millisecondTimestampThreshold uint64 = 1_000_000_000_000

// IsMillisecondsTimestamp reports whether ts is encoded as Unix milliseconds.
func IsMillisecondsTimestamp(ts uint64) bool {
	return ts >= millisecondTimestampThreshold
}

// UnixTimestampToTime converts a Unix timestamp encoded in either seconds or
// milliseconds to time.Time.
func UnixTimestampToTime(ts uint64) time.Time {
	if IsMillisecondsTimestamp(ts) {
		return time.UnixMilli(int64(ts))
	}
	return time.Unix(int64(ts), 0)
}
