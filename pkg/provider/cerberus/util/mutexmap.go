package util

import (
	"sync"
)

type MutexMap struct {
	sync.Map
}

func (m *MutexMap) GetLock(key string) *sync.RWMutex {
	lock, _ := m.LoadOrStore(key, &sync.RWMutex{})

	return lock.(*sync.RWMutex)
}
