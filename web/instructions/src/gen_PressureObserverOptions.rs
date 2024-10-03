use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    # [wasm_bindgen (extends = :: web_sys::js_sys :: Object , js_name = PressureObserverOptions)]
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[doc = "The `PressureObserverOptions` dictionary."]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserverOptions`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub type PressureObserverOptions;

    #[doc = "Get the `sampleInterval` field of this object."]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserverOptions`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    #[wasm_bindgen(method, getter = "sampleInterval")]
    pub fn get_sample_interval(this: &PressureObserverOptions) -> Option<u32>;

    #[doc = "Change the `sampleInterval` field of this object."]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserverOptions`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    #[wasm_bindgen(method, setter = "sampleInterval")]
    pub fn set_sample_interval(this: &PressureObserverOptions, val: u32);
}

impl PressureObserverOptions {
    #[doc = "Construct a new `PressureObserverOptions`."]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `PressureObserverOptions`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn new() -> Self {
        #[allow(unused_mut)]
        let mut ret: Self = ::wasm_bindgen::JsCast::unchecked_into(web_sys::js_sys::Object::new());
        ret
    }

    #[deprecated = "Use `set_sample_interval()` instead."]
    pub fn sample_interval(&mut self, val: u32) -> &mut Self {
        self.set_sample_interval(val);
        self
    }
}

impl Default for PressureObserverOptions {
    fn default() -> Self {
        Self::new()
    }
}
