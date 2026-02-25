package params

import "time"

// UnixTimestampToTime converts a Unix millisecond timestamp to time.Time.
func UnixTimestampToTime(ts uint64) time.Time {
	return time.UnixMilli(int64(ts))
}
