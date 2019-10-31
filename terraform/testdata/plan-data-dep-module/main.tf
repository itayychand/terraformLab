module "mod" {
  source = "./mod"
}

data "test_file" "d" {
  template = module.mod.out
}
