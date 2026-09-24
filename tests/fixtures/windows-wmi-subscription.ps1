# Creates and removes an inert permanent WMI subscription for sensor testing.
# The filter watches instance creation of a class whose instances are never
# created. The consumer command would exit immediately if invoked.
$ErrorActionPreference = 'Stop'
$namespace = 'root\subscription'
$name = 'RustinelWmiFixture'

$filter = $null
$consumer = $null
$binding = $null
try {
    $filter = Set-WmiInstance -Namespace $namespace -Class __EventFilter -Arguments @{
        Name = $name
        EventNamespace = 'root\cimv2'
        QueryLanguage = 'WQL'
        Query = "SELECT * FROM __InstanceCreationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime'"
    }
    $consumer = Set-WmiInstance -Namespace $namespace -Class CommandLineEventConsumer -Arguments @{
        Name = $name
        CommandLineTemplate = 'cmd.exe /c exit 0'
    }
    $binding = Set-WmiInstance -Namespace $namespace -Class __FilterToConsumerBinding -Arguments @{
        Filter = $filter
        Consumer = $consumer
    }
    Start-Sleep -Seconds 3
} finally {
    foreach ($instance in @($binding, $consumer, $filter)) {
        if ($instance) { $instance.Delete() }
    }
}
