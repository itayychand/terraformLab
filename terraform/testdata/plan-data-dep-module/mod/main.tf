resource "test_instance" "a" {
  compute = "value"
}

output "out" {
  value = test_instance.a.value
}
