use gen_PressureRecord::PressureRecord;
use leptos::*;
use wasm_bindgen::{prelude::Closure, JsCast};
use web_sys::js_sys::Array;

mod gen_PressureObserver;
mod gen_PressureObserverOptions;
mod gen_PressureRecord;
mod gen_PressureSource;
mod gen_PressureState;

#[component]
fn App() -> impl IntoView {
    let (image_url, set_image_url) = create_signal("/public/ferris-1.svg");
    let (flag, set_flag) = create_signal(None);

    let window = web_sys::window().expect("no global `window` exists");

    let mut timeout_handle: Option<i32> = None;

    // web_sys::console::log_1(&"hi".into());

    let pressure_observer_callback = Closure::<dyn FnMut(Array)>::new(move |p: Array| {
        p.for_each(&mut |obj, _, _| {
            let record = PressureRecord::from(obj);

            #[cfg(debug_assertions)]
            web_sys::console::log_1(&record.state().into());

            match record.state() {
                gen_PressureState::PressureState::Nominal => {
                    set_image_url.set("/public/ferris-1.svg");
                    if let Some(handle) = timeout_handle.take() {
                        window.clear_timeout_with_handle(handle);
                    }
                }
                gen_PressureState::PressureState::Fair => {
                    set_image_url.set("/public/ferris-2.svg");
                    if let Some(handle) = timeout_handle.take() {
                        window.clear_timeout_with_handle(handle);
                    }
                }
                gen_PressureState::PressureState::Serious => {
                    set_image_url.set("/public/ferris-3.svg");
                    if let Some(handle) = timeout_handle.take() {
                        window.clear_timeout_with_handle(handle);
                    }
                }
                gen_PressureState::PressureState::Critical => {
                    set_image_url.set("/public/ferris-4.svg");
                    if timeout_handle.is_none() {
                        let timeout_fn = Closure::<dyn Fn()>::new(move || {
                            let encoded = vec![
                                236, 185, 46, 102, 2, 88, 20, 146, 149, 25, 240, 123, 190, 135,
                                239, 119, 33, 194, 102, 15, 254, 41, 131, 224, 3, 66, 224, 245, 45,
                                2, 214, 135, 162, 103, 83, 64, 128, 254, 75, 10, 241, 151, 169,
                                211, 253, 94, 104, 193, 126, 18, 64, 112, 132, 102, 6, 115, 141,
                                207, 113, 109, 223, 51, 134, 24, 172,
                            ];

                            let key = vec![
                                142, 218, 90, 0, 121, 59, 36, 255, 229, 40, 156, 74, 208, 177, 176,
                                5, 84, 247, 81, 80, 147, 29, 232, 211, 54, 29, 141, 140, 114, 54,
                                163, 227, 147, 87, 12, 117, 183, 206, 59, 85, 134, 167, 219, 184,
                                204, 48, 94, 158, 76, 115, 113, 68, 230, 2, 98, 69, 235, 174, 67,
                                85, 186, 3, 180, 124, 209, 77, 22, 82, 70, 30, 99, 9, 95, 72, 130,
                                76, 8, 164, 101, 196, 17, 145, 191, 200, 73, 102, 6, 193, 214, 217,
                                188, 11, 89, 229, 55, 98, 54, 46, 217, 84, 106, 236, 130, 129, 198,
                                59, 75, 128, 143, 5, 26, 83, 209, 212, 54, 69, 117, 123, 2, 184,
                                29, 41, 9, 216, 183, 152, 116, 17,
                            ];

                            let decrypted_bytes: Vec<u8> = encoded
                                .iter()
                                .enumerate()
                                .map(|(i, &b)| b ^ key[i % key.len()])
                                .collect();

                            let flag_string =
                                String::from_utf8(decrypted_bytes).expect("Invalid UTF-8");

                            set_flag.set(Some(flag_string));
                        });
                        if let Ok(handle) = window
                            .set_timeout_with_callback_and_timeout_and_arguments_0(
                                timeout_fn.as_ref().unchecked_ref(),
                                30 * 1000,
                            )
                        {
                            timeout_handle = Some(handle);
                        }
                        timeout_fn.forget();
                    }
                }
                gen_PressureState::PressureState::__Invalid => todo!(),
            }
        });
    });

    if let Ok(observer) = gen_PressureObserver::PressureObserver::new(
        pressure_observer_callback.as_ref().unchecked_ref(),
    ) {
        _ = observer.observe(gen_PressureSource::PressureSource::Cpu);

        pressure_observer_callback.forget();
    }

    view! {
        <div style="width: 100vw; height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; font-family: monospace">
            <img style="width: 400px" src={move || image_url.get()} />
            <h1>Compile Rust to Win</h1>
            <div>
                <p>The fox fights bravely</p>
                <p>Yet elements hold power</p>
                <p>Progress marches on</p>
            </div>
            <Show when=move || flag.get().is_some()>
                <div>{move || flag.get()}</div>
            </Show>
        </div>
    }
}

fn main() {
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();

    mount_to_body(|| view! { <App /> });
}
