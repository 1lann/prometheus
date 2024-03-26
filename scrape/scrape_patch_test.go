// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scrape

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/model/textparse"
)

func TestHideUnusedMetrics(t *testing.T) {
	testPayload := []byte(`# TYPE acme_http_router_request_seconds summary
# UNIT acme_http_router_request_seconds seconds
# HELP acme_http_router_request_seconds Latency though all of ACME's HTTP request router.
acme_http_router_request_seconds_sum{path="/api/v1",method="GET"} 9036.32
acme_http_router_request_seconds_count{path="/api/v1",method="GET"} 807283.0
acme_http_router_request_seconds_created{path="/api/v1",method="GET"} 1605281325.0
acme_http_router_request_seconds_sum{path="/api/v2",method="POST"} 479.3
acme_http_router_request_seconds_count{path="/api/v2",method="POST"} 34.0
acme_http_router_request_seconds_created{path="/api/v2",method="POST"} 1605281325.0
# TYPE go_goroutines gauge
# HELP go_goroutines Number of goroutines that currently exist.
go_goroutines 69
# TYPE process_cpu_seconds counter
# UNIT process_cpu_seconds seconds
# HELP process_cpu_seconds Total user and system CPU time spent in seconds.
process_cpu_seconds_total 4.20072246e+06
# EOF`)

	if !bytes.Equal(hideUnusedMetrics(testPayload), testPayload) {
		t.Fatal("hide unused metrics on no registered used metrics should be a no-op")
	}

	usedMetricsTrie.Add(strings.Split("acme_http_router_request_seconds", "_"))

	if !bytes.Equal(hideUnusedMetrics(testPayload), []byte(`# TYPE acme_http_router_request_seconds summary
# UNIT acme_http_router_request_seconds seconds
# HELP acme_http_router_request_seconds Latency though all of ACME's HTTP request router.
acme_http_router_request_seconds_sum{path="/api/v1",method="GET"} 9036.32
acme_http_router_request_seconds_count{path="/api/v1",method="GET"} 807283.0
acme_http_router_request_seconds_created{path="/api/v1",method="GET"} 1605281325.0
acme_http_router_request_seconds_sum{path="/api/v2",method="POST"} 479.3
acme_http_router_request_seconds_count{path="/api/v2",method="POST"} 34.0
acme_http_router_request_seconds_created{path="/api/v2",method="POST"} 1605281325.0
# EOF
`)) {
		t.Fatal("hide unused metrics on acme_http_router_request_seconds part 1 does not match expected")
	}

	usedMetricsTrie.Add(strings.Split("process_cpu_seconds", "_"))

	if !bytes.Equal(hideUnusedMetrics(testPayload), []byte(`# TYPE acme_http_router_request_seconds summary
# UNIT acme_http_router_request_seconds seconds
# HELP acme_http_router_request_seconds Latency though all of ACME's HTTP request router.
acme_http_router_request_seconds_sum{path="/api/v1",method="GET"} 9036.32
acme_http_router_request_seconds_count{path="/api/v1",method="GET"} 807283.0
acme_http_router_request_seconds_created{path="/api/v1",method="GET"} 1605281325.0
acme_http_router_request_seconds_sum{path="/api/v2",method="POST"} 479.3
acme_http_router_request_seconds_count{path="/api/v2",method="POST"} 34.0
acme_http_router_request_seconds_created{path="/api/v2",method="POST"} 1605281325.0
# TYPE process_cpu_seconds counter
# UNIT process_cpu_seconds seconds
# HELP process_cpu_seconds Total user and system CPU time spent in seconds.
process_cpu_seconds_total 4.20072246e+06
# EOF
`)) {
		t.Fatal("hide unused metrics on acme_http_router_request_seconds part 2 does not match expected")
	}

	for _, metric := range realMetricsUsed {
		usedMetricsTrie.Add(strings.Split(metric, "_"))
	}

	data := hideUnusedMetrics([]byte(sqlproberPayload))

	p := textparse.NewPromParser(data)
	for {
		ent, err := p.Next()
		log.Printf("entry: %+v, err: %v", ent, err)
		if err != nil {
			break
		}
	}
}

var realMetricsUsed = []string{"backup_last_failed_time_kms_inaccessible", "capacity", "capacity_available", "cc_managed_rpo", "cluster:capacity", "cluster:capacity_available", "cluster:capacity_available:ratio", "cmek_kms_init_failure", "fluentbit_output_proc_bytes_total", "fluentbit_output_retries_failed_total", "is_cluster_disrupted", "jobs_adopt_iterations", "kube_deployment_status_replicas_ready", "kube_pod_container_status_last_terminated_reason", "kube_pod_container_status_restarts_total", "kube_pod_spec_volumes_persistentvolumeclaims_info", "kube_pod_status_phase", "kube_pod_status_ready", "kubelet:pv:bytes_used:ratio", "kubelet_volume_stats_capacity_bytes", "kubelet_volume_stats_used_bytes", "kv_prober_write_attempts", "kv_prober_write_failures", "last_successful_full_or_incremental_backup", "log_fluent_sink_conn_errors", "log_fluent_sink_write_attempts", "log_fluent_sink_write_errors", "node:capacity", "node:capacity_available", "node:capacity_available:ratio", "node_decommissioning", "node_filesystem_avail_bytes", "node_filesystem_files", "node_filesystem_files_free", "node_filesystem_size_bytes", "node_memory_MemAvailable_bytes", "node_memory_MemTotal_bytes", "otelcol_receiver_accepted_metric_points", "prometheus_remote_storage_highest_timestamp_in_seconds", "prometheus_remote_storage_queue_highest_sent_timestamp_seconds", "prometheus_remote_storage_samples_failed_total", "prometheus_remote_storage_samples_total", "prometheus_rule_evaluation_failures_total", "ranges_unavailable", "schedules_BACKUP_last_completed_time", "security_certificate_expiration_ui", "sqlprober_dedicated_failures", "sqlprober_dedicated_runs", "sys_cpu_combined_percent_normalized", "sys_fd_open", "sys_fd_softlimit", "up"}

const sqlproberPayload = `# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 7.45e-05
go_gc_duration_seconds{quantile="0.25"} 8.99e-05
go_gc_duration_seconds{quantile="0.5"} 0.000118501
go_gc_duration_seconds{quantile="0.75"} 0.000149001
go_gc_duration_seconds{quantile="1"} 0.007810164
go_gc_duration_seconds_sum 0.567682729
go_gc_duration_seconds_count 2356
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 17
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.21.3 X:nocoverageredesign"} 1
# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 6.41672e+06
# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.
# TYPE go_memstats_alloc_bytes_total counter
go_memstats_alloc_bytes_total 5.842602496e+09
# HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table.
# TYPE go_memstats_buck_hash_sys_bytes gauge
go_memstats_buck_hash_sys_bytes 5758
# HELP go_memstats_frees_total Total number of frees.
# TYPE go_memstats_frees_total counter
go_memstats_frees_total 5.1001959e+07
# HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata.
# TYPE go_memstats_gc_sys_bytes gauge
go_memstats_gc_sys_bytes 4.765152e+06
# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 6.41672e+06
# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used.
# TYPE go_memstats_heap_idle_bytes gauge
go_memstats_heap_idle_bytes 7.061504e+06
# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use.
# TYPE go_memstats_heap_inuse_bytes gauge
go_memstats_heap_inuse_bytes 8.896512e+06
# HELP go_memstats_heap_objects Number of allocated objects.
# TYPE go_memstats_heap_objects gauge
go_memstats_heap_objects 21000
# HELP go_memstats_heap_released_bytes Number of heap bytes released to OS.
# TYPE go_memstats_heap_released_bytes gauge
go_memstats_heap_released_bytes 4.42368e+06
# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system.
# TYPE go_memstats_heap_sys_bytes gauge
go_memstats_heap_sys_bytes 1.5958016e+07
# HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
# TYPE go_memstats_last_gc_time_seconds gauge
go_memstats_last_gc_time_seconds 1.7114081846955912e+09
# HELP go_memstats_lookups_total Total number of pointer lookups.
# TYPE go_memstats_lookups_total counter
go_memstats_lookups_total 0
# HELP go_memstats_mallocs_total Total number of mallocs.
# TYPE go_memstats_mallocs_total counter
go_memstats_mallocs_total 5.1022959e+07
# HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures.
# TYPE go_memstats_mcache_inuse_bytes gauge
go_memstats_mcache_inuse_bytes 2400
# HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system.
# TYPE go_memstats_mcache_sys_bytes gauge
go_memstats_mcache_sys_bytes 15600
# HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures.
# TYPE go_memstats_mspan_inuse_bytes gauge
go_memstats_mspan_inuse_bytes 128520
# HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system.
# TYPE go_memstats_mspan_sys_bytes gauge
go_memstats_mspan_sys_bytes 162960
# HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place.
# TYPE go_memstats_next_gc_bytes gauge
go_memstats_next_gc_bytes 1.1794424e+07
# HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations.
# TYPE go_memstats_other_sys_bytes gauge
go_memstats_other_sys_bytes 529970
# HELP go_memstats_stack_inuse_bytes Number of bytes in use by the stack allocator.
# TYPE go_memstats_stack_inuse_bytes gauge
go_memstats_stack_inuse_bytes 819200
# HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator.
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 819200
# HELP go_memstats_sys_bytes Number of bytes obtained from system.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 2.2256656e+07
# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 9
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 216.22
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1.048576e+06
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 13
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 2.138112e+07
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.71112839693e+09
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 1.279561728e+09
# HELP process_virtual_memory_max_bytes Maximum amount of virtual memory available in bytes.
# TYPE process_virtual_memory_max_bytes gauge
process_virtual_memory_max_bytes 1.8446744073709552e+19
# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
# TYPE promhttp_metric_handler_requests_in_flight gauge
promhttp_metric_handler_requests_in_flight 1
# HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
# TYPE promhttp_metric_handler_requests_total counter
promhttp_metric_handler_requests_total{code="200"} 8568
promhttp_metric_handler_requests_total{code="500"} 0
promhttp_metric_handler_requests_total{code="503"} 0
# HELP sqlprober_dedicated_failures Count of probe failures
# TYPE sqlprober_dedicated_failures counter
sqlprober_dedicated_failures{collection="",probe="connect"} 14
sqlprober_dedicated_failures{collection="",probe="selectone"} 12
# HELP sqlprober_dedicated_latency_ns Distribution of probe latency in nanoseconds
# TYPE sqlprober_dedicated_latency_ns histogram
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.0904938940366164e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.1891769329311433e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.2967901842906026e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.4141417778155208e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.5421129740099108e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.6816647820724554e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.8338451766664297e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.9997969677632416e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.1807663826587554e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.3781124246096923e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.593317078369483e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.8279964392627985e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.0839128493733746e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.362988131982729e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.6673180236447724e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.999187912275056e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.361089999440992e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.755742015734553e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.186107629771921e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.655418704082988e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.167199565022973e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.72529346896283e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="7.3338914635083e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="7.997563860483065e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="8.721294557024695e+06"} 0
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="9.510518462530205e+06"} 26
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.03711623125117e+07"} 2733
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.1309689175856683e+07"} 5921
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.2333146989723725e+07"} 10353
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.3449221486549798e+07"} 16738
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.466629391062862e+07"} 20616
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.599350395768692e+07"} 22672
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.744081841010805e+07"} 24128
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.901910598322423e+07"} 25015
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.0740218944741305e+07"} 25762
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.261708212022295e+07"} 26284
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.4663789953027856e+07"} 26660
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.6895712347578526e+07"} 26948
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.932961009079961e+07"} 27173
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.198376071849171e+07"} 27337
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.4878095771843396e+07"} 27465
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.803435047481955e+07"} 27559
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.1476226956439406e+07"} 27625
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.5229572243674085e+07"} 27680
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.9322572361614615e+07"} 27727
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.378596399851992e+07"} 27767
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.865326532525924e+07"} 27789
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.39610277025048e+07"} 27808
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.974911016588835e+07"} 27824
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="7.606097875038855e+07"} 27832
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="8.294403290174755e+07"} 27837
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="9.044996142612791e+07"} 27848
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="9.863513065103997e+07"} 27853
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.07561007712463e+08"} 27856
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.1729462214686632e+08"} 27858
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.279090692544898e+08"} 27859
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.3948405901392785e+08"} 27860
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.5210651467013136e+08"} 27862
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.6587122549096933e+08"} 27862
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.8088155859427276e+08"} 27864
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.9725023519088092e+08"} 27864
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.151001770729422e+08"} 27864
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.345654297042384e+08"} 27865
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.5579216884454718e+08"} 27865
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.7893979826736194e+08"} 27865
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.041821468143638e+08"} 27866
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.317087737760133e+08"} 27869
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.617263924011158e+08"} 27869
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.944604222253099e+08"} 27870
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.301566818758061e+08"} 27871
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.690832350646178e+08"} 27875
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.115324036329086e+08"} 27875
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.578229627635608e+08"} 27875
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.083025348470778e+08"} 27877
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.633501999777346e+08"} 27877
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="7.233793426836879e+08"} 27878
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="7.888407562687829e+08"} 27878
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="8.602260280783345e+08"} 27879
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="9.380712311107947e+08"} 27879
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.0229609496977332e+09"} 27881
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.1155326694832764e+09"} 27883
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.21648156466988e+09"} 27886
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.3265657184806135e+09"} 27886
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.446611816041406e+09"} 27886
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.5775213524343743e+09"} 27887
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.7202774025420704e+09"} 27887
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.8759520035212982e+09"} 27887
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.0457142053457327e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.2308388498734913e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.4327161443667097e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.652862101356197e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.89292992325008e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.15472241718003e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.440205533315258e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.75152312831127e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.0910130647605863e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.4612247675454445e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.864938368933229e+09"} 27888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.305185586186144e+09"} 27890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.785272488467058e+09"} 27890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.308804324011348e+09"} 27890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.879712594006179e+09"} 27890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="7.502284576490549e+09"} 27890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="8.181195521988027e+09"} 27890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="8.921543762647654e+09"} 27891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="9.728888998547726e+09"} 27891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.0609294048676308e+10"} 27894
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.1569370380120527e+10"} 27894
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.2616327757369522e+10"} 27894
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.3758028384576143e+10"} 27896
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.5003045947362736e+10"} 27897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.6360729997549868e+10"} 27899
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.7841276164309834e+10"} 27899
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="1.94558027190009e+10"} 27900
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.1216434068651485e+10"} 27901
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.313639180509489e+10"} 27902
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.5230093993494785e+10"} 27902
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="2.751326344587598e+10"} 27903
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.0003045792748592e+10"} 27905
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.2718138239493332e+10"} 27905
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.567892997441342e+10"} 27905
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="3.8907655282857834e+10"} 27905
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.242856051723798e+10"} 27905
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="4.626808617681108e+10"} 27905
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.045506546457245e+10"} 27905
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="5.502094081233402e+10"} 27906
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="6.000000000000032e+10"} 27906
sqlprober_dedicated_latency_ns_bucket{collection="",probe="connect",le="+Inf"} 27906
sqlprober_dedicated_latency_ns_sum{collection="",probe="connect"} 7.3397487046e+11
sqlprober_dedicated_latency_ns_count{collection="",probe="connect"} 27906
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1e+06"} 8099
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.0904938940366164e+06"} 13716
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.1891769329311433e+06"} 21502
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.2967901842906026e+06"} 29154
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.4141417778155208e+06"} 35481
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.5421129740099108e+06"} 39879
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.6816647820724554e+06"} 42739
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.8338451766664297e+06"} 44432
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.9997969677632416e+06"} 45643
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.1807663826587554e+06"} 46683
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.3781124246096923e+06"} 47630
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.593317078369483e+06"} 48576
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.8279964392627985e+06"} 49467
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.0839128493733746e+06"} 50267
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.362988131982729e+06"} 50953
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.6673180236447724e+06"} 51522
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.999187912275056e+06"} 51984
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.361089999440992e+06"} 52488
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.755742015734553e+06"} 52793
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.186107629771921e+06"} 53040
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.655418704082988e+06"} 53246
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.167199565022973e+06"} 53419
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.72529346896283e+06"} 53574
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="7.3338914635083e+06"} 53691
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="7.997563860483065e+06"} 53795
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="8.721294557024695e+06"} 53913
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="9.510518462530205e+06"} 53974
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.03711623125117e+07"} 54084
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.1309689175856683e+07"} 54340
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.2333146989723725e+07"} 54534
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.3449221486549798e+07"} 54887
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.466629391062862e+07"} 55208
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.599350395768692e+07"} 55404
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.744081841010805e+07"} 55531
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.901910598322423e+07"} 55608
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.0740218944741305e+07"} 55684
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.261708212022295e+07"} 55734
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.4663789953027856e+07"} 55771
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.6895712347578526e+07"} 55798
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.932961009079961e+07"} 55816
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.198376071849171e+07"} 55834
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.4878095771843396e+07"} 55846
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.803435047481955e+07"} 55855
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.1476226956439406e+07"} 55865
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.5229572243674085e+07"} 55874
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.9322572361614615e+07"} 55878
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.378596399851992e+07"} 55881
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.865326532525924e+07"} 55883
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.39610277025048e+07"} 55885
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.974911016588835e+07"} 55885
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="7.606097875038855e+07"} 55885
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="8.294403290174755e+07"} 55886
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="9.044996142612791e+07"} 55887
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="9.863513065103997e+07"} 55888
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.07561007712463e+08"} 55889
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.1729462214686632e+08"} 55889
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.279090692544898e+08"} 55889
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.3948405901392785e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.5210651467013136e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.6587122549096933e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.8088155859427276e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.9725023519088092e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.151001770729422e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.345654297042384e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.5579216884454718e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.7893979826736194e+08"} 55890
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.041821468143638e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.317087737760133e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.617263924011158e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.944604222253099e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.301566818758061e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.690832350646178e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.115324036329086e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.578229627635608e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.083025348470778e+08"} 55891
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.633501999777346e+08"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="7.233793426836879e+08"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="7.888407562687829e+08"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="8.602260280783345e+08"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="9.380712311107947e+08"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.0229609496977332e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.1155326694832764e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.21648156466988e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.3265657184806135e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.446611816041406e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.5775213524343743e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.7202774025420704e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.8759520035212982e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.0457142053457327e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.2308388498734913e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.4327161443667097e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.652862101356197e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.89292992325008e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.15472241718003e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.440205533315258e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.75152312831127e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.0910130647605863e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.4612247675454445e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.864938368933229e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.305185586186144e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.785272488467058e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.308804324011348e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.879712594006179e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="7.502284576490549e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="8.181195521988027e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="8.921543762647654e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="9.728888998547726e+09"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.0609294048676308e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.1569370380120527e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.2616327757369522e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.3758028384576143e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.5003045947362736e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.6360729997549868e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.7841276164309834e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="1.94558027190009e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.1216434068651485e+10"} 55892
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.313639180509489e+10"} 55893
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.5230093993494785e+10"} 55893
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="2.751326344587598e+10"} 55893
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.0003045792748592e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.2718138239493332e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.567892997441342e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="3.8907655282857834e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.242856051723798e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="4.626808617681108e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.045506546457245e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="5.502094081233402e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="6.000000000000032e+10"} 55897
sqlprober_dedicated_latency_ns_bucket{collection="",probe="selectone",le="+Inf"} 55897
sqlprober_dedicated_latency_ns_sum{collection="",probe="selectone"} 2.53448720852e+11
sqlprober_dedicated_latency_ns_count{collection="",probe="selectone"} 55897
# HELP sqlprober_dedicated_runs Count of probe runs
# TYPE sqlprober_dedicated_runs counter
sqlprober_dedicated_runs{collection="",probe="connect"} 27906
sqlprober_dedicated_runs{collection="",probe="selectone"} 55897`
