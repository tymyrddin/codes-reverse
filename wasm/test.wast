(module
  (export "sqrt" (func $sqrt))
  (func $sqrt
    (param $num f64)
    (result f64)
    (f64.sqrt (get_local $num))
  )
)