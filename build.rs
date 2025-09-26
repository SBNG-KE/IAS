fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("ias.ico");
    res.compile().unwrap();
}
