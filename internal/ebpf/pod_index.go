package ebpf

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type podIndex struct {
	mu          sync.RWMutex
	byUID       map[string]podInfo
	byContainer map[string]podInfo
}

type podsListResponse struct {
	Items []struct {
		Metadata struct {
			UID       string `json:"uid"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

func newPodIndex() *podIndex {
	return &podIndex{
		byUID:       make(map[string]podInfo),
		byContainer: make(map[string]podInfo),
	}
}

func (p *podIndex) Start(stop <-chan struct{}) {
	p.refresh()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				p.refresh()
			}
		}
	}()
}

func (p *podIndex) Resolve(uid, containerID string) podInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if containerID != "" {
		if info, ok := p.byContainer[containerID]; ok {
			return info
		}
	}
	if uid != "" {
		if info, ok := p.byUID[uid]; ok {
			return info
		}
	}
	return podInfo{}
}

func (p *podIndex) refresh() {
	resp, err := fetchPods()
	if err != nil {
		return
	}
	nextUID := make(map[string]podInfo, len(resp.Items))
	nextContainer := make(map[string]podInfo, len(resp.Items)*2)

	for _, it := range resp.Items {
		info := podInfo{
			Namespace: it.Metadata.Namespace,
			Pod:       it.Metadata.Name,
			Node:      it.Spec.NodeName,
		}
		nextUID[it.Metadata.UID] = info
		for _, st := range it.Status.ContainerStatuses {
			cid := strings.TrimPrefix(st.ContainerID, "containerd://")
			cid = strings.TrimPrefix(cid, "docker://")
			if cid != "" {
				nextContainer[cid] = info
			}
		}
	}

	p.mu.Lock()
	p.byUID = nextUID
	p.byContainer = nextContainer
	p.mu.Unlock()
}

func fetchPods() (*podsListResponse, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return &podsListResponse{}, nil
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, os.ErrInvalid
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+host+":"+port+"/api/v1/pods", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var out podsListResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
